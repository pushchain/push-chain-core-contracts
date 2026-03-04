// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../../src/UniversalCore.sol";
import "../../src/PRC20.sol";
import "../../src/interfaces/IPRC20.sol";
import "../../src/interfaces/IUniversalCore.sol";
import {UniversalCoreErrors, CommonErrors} from "../../src/libraries/Errors.sol";
import "../../test/helpers/UpgradeableContractHelper.sol";
import "../../test/mocks/MockUniswapV3Factory.sol";
import "../../test/mocks/MockUniswapV3Router.sol";
import "../../test/mocks/MockUniswapV3Quoter.sol";
import "../../test/mocks/MockWPC.sol";
import "../../test/mocks/MockPRC20.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

contract UniversalCoreWithdrawFeeTest is Test, UpgradeableContractHelper {
    UniversalCore public universalCore;
    PRC20 public prc20Token;
    MockUniswapV3Factory public mockFactory;
    MockUniswapV3Router public mockRouter;
    MockUniswapV3Quoter public mockQuoter;
    MockWPC public mockWPC;
    MockPRC20 public mockPRC20;

    address public constant UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;
    string public constant SOURCE_TOKEN_ADDRESS = "0x0000000000000000000000000000000000000000";

    address public deployer;
    address public nonOwner;

    string public constant CHAIN_NAMESPACE = "eip155:1";
    uint256 public constant BASE_GAS_LIMIT = 500_000;
    uint256 public constant PROTOCOL_FEE = 1000;
    uint256 public constant GAS_PRICE = 50 * 10 ** 9; // 50 gwei
    uint24 public constant FEE_TIER = 3000;
    uint256 public constant GAS_TO_PC_RATE = 2500e18; // 1 pETH = 2500 PC

    event SetGasToPCRate(string chainNamespace, uint256 rate);

    function setUp() public {
        deployer = address(this);
        nonOwner = makeAddr("nonOwner");

        // Deploy mocks
        mockFactory = new MockUniswapV3Factory();
        mockRouter = new MockUniswapV3Router();
        mockQuoter = new MockUniswapV3Quoter();
        mockWPC = new MockWPC();
        mockPRC20 = new MockPRC20();

        // Deploy PRC20 token via proxy
        PRC20 implementationPrc20 = new PRC20();
        bytes memory initDataPrc20 = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "Test PRC20",
            "TPRC20",
            18,
            CHAIN_NAMESPACE,
            IPRC20.TokenType.ERC20,
            PROTOCOL_FEE,
            address(0x1),
            SOURCE_TOKEN_ADDRESS
        );
        address proxyAddressPrc20 = deployUpgradeableContract(address(implementationPrc20), initDataPrc20);
        prc20Token = PRC20(payable(proxyAddressPrc20));

        // Deploy UniversalCore via proxy
        UniversalCore implementation = new UniversalCore();
        bytes memory initData = abi.encodeWithSelector(
            UniversalCore.initialize.selector,
            address(mockWPC),
            address(mockFactory),
            address(mockRouter),
            address(mockQuoter)
        );
        address proxyAddress = deployUpgradeableContract(address(implementation), initData);
        universalCore = UniversalCore(payable(proxyAddress));

        // Update PRC20 universalCore
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        prc20Token.updateUniversalCore(address(universalCore));

        // Setup mock pool
        address pool = makeAddr("mockPool");
        mockFactory.setPool(address(mockWPC), address(prc20Token), FEE_TIER, pool);

        // Set BASE_GAS_LIMIT (proxy storage defaults to 0)
        universalCore.updateBaseGasLimit(BASE_GAS_LIMIT);

        // Configure gas price, gas token, and gas-to-PC rate
        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasPrice(CHAIN_NAMESPACE, GAS_PRICE);
        universalCore.setGasTokenPRC20(CHAIN_NAMESPACE, address(mockPRC20));
        universalCore.setGasToPCRate(CHAIN_NAMESPACE, GAS_TO_PC_RATE);
        vm.stopPrank();
    }

    // ========================================
    // 1) setGasToPCRate
    // ========================================

    function test_SetGasToPCRate_HappyPath() public {
        uint256 newRate = 3000e18;
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasToPCRate(CHAIN_NAMESPACE, newRate);
        assertEq(universalCore.gasToPCRateByChainNamespace(CHAIN_NAMESPACE), newRate);
    }

    function test_SetGasToPCRate_ZeroRateAllowed() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasToPCRate(CHAIN_NAMESPACE, 0);
        assertEq(universalCore.gasToPCRateByChainNamespace(CHAIN_NAMESPACE), 0);
    }

    function test_SetGasToPCRate_NonManager_Reverts() public {
        bytes32 managerRole = universalCore.MANAGER_ROLE();
        vm.prank(nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                nonOwner,
                managerRole
            )
        );
        universalCore.setGasToPCRate(CHAIN_NAMESPACE, GAS_TO_PC_RATE);
    }

    function test_SetGasToPCRate_Admin_Reverts() public {
        // Deployer has DEFAULT_ADMIN_ROLE but not MANAGER_ROLE
        bytes32 managerRole = universalCore.MANAGER_ROLE();
        vm.prank(deployer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                deployer,
                managerRole
            )
        );
        universalCore.setGasToPCRate(CHAIN_NAMESPACE, GAS_TO_PC_RATE);
    }

    function test_SetGasToPCRate_UpdateExistingRate() public {
        uint256 firstRate = 2000e18;
        uint256 secondRate = 4000e18;

        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasToPCRate(CHAIN_NAMESPACE, firstRate);
        assertEq(universalCore.gasToPCRateByChainNamespace(CHAIN_NAMESPACE), firstRate);

        universalCore.setGasToPCRate(CHAIN_NAMESPACE, secondRate);
        assertEq(universalCore.gasToPCRateByChainNamespace(CHAIN_NAMESPACE), secondRate);
        vm.stopPrank();
    }

    function test_SetGasToPCRate_MultipleChains() public {
        string memory bscNamespace = "eip155:56";
        uint256 ethRate = 2500e18;
        uint256 bscRate = 600e18;

        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasToPCRate(CHAIN_NAMESPACE, ethRate);
        universalCore.setGasToPCRate(bscNamespace, bscRate);
        vm.stopPrank();

        assertEq(universalCore.gasToPCRateByChainNamespace(CHAIN_NAMESPACE), ethRate);
        assertEq(universalCore.gasToPCRateByChainNamespace(bscNamespace), bscRate);
    }

    function test_SetGasToPCRate_EmitsEvent() public {
        uint256 newRate = 3500e18;

        vm.expectEmit(false, false, false, true);
        emit SetGasToPCRate(CHAIN_NAMESPACE, newRate);

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasToPCRate(CHAIN_NAMESPACE, newRate);
    }

    // ========================================
    // 2) withdrawGasFeeInPC
    // ========================================

    function test_WithdrawGasFeeInPC_HappyPath() public view {
        uint256 pcFee = universalCore.withdrawGasFeeInPC(address(prc20Token));

        uint256 expectedGasFee = GAS_PRICE * BASE_GAS_LIMIT + PROTOCOL_FEE;
        uint256 expectedPcFee = (expectedGasFee * GAS_TO_PC_RATE) / 1e18;
        assertEq(pcFee, expectedPcFee);
    }

    function test_WithdrawGasFeeInPC_ZeroRate_Reverts() public {
        // Clear the rate
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasToPCRate(CHAIN_NAMESPACE, 0);

        vm.expectRevert(UniversalCoreErrors.ZeroGasToPCRate.selector);
        universalCore.withdrawGasFeeInPC(address(prc20Token));
    }

    function test_WithdrawGasFeeInPC_ZeroGasPrice_Reverts() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasPrice(CHAIN_NAMESPACE, 0);

        vm.expectRevert(UniversalCoreErrors.ZeroGasPrice.selector);
        universalCore.withdrawGasFeeInPC(address(prc20Token));
    }

    function test_WithdrawGasFeeInPC_ZeroGasToken_Reverts() public {
        // Create a PRC20 with a chain namespace that has no gas token set
        PRC20 newPrc20 = new PRC20();
        bytes memory initData = abi.encodeWithSelector(
            PRC20.initialize.selector,
            "New PRC20",
            "NPRC20",
            18,
            "eip155:999",
            IPRC20.TokenType.ERC20,
            PROTOCOL_FEE,
            address(universalCore),
            SOURCE_TOKEN_ADDRESS
        );
        address proxyAddress = deployUpgradeableContract(address(newPrc20), initData);

        vm.expectRevert(CommonErrors.ZeroAddress.selector);
        universalCore.withdrawGasFeeInPC(proxyAddress);
    }

    function test_WithdrawGasFeeInPC_AfterRateUpdate() public {
        uint256 pcFeeBefore = universalCore.withdrawGasFeeInPC(address(prc20Token));

        // Double the rate
        uint256 doubleRate = GAS_TO_PC_RATE * 2;
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasToPCRate(CHAIN_NAMESPACE, doubleRate);

        uint256 pcFeeAfter = universalCore.withdrawGasFeeInPC(address(prc20Token));
        assertEq(pcFeeAfter, pcFeeBefore * 2);
    }

    function test_WithdrawGasFeeInPC_AfterGasPriceUpdate() public {
        uint256 newGasPrice = GAS_PRICE * 2;
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasPrice(CHAIN_NAMESPACE, newGasPrice);

        uint256 pcFee = universalCore.withdrawGasFeeInPC(address(prc20Token));

        uint256 expectedGasFee = newGasPrice * BASE_GAS_LIMIT + PROTOCOL_FEE;
        uint256 expectedPcFee = (expectedGasFee * GAS_TO_PC_RATE) / 1e18;
        assertEq(pcFee, expectedPcFee);
    }

    function test_WithdrawGasFeeInPC_AfterProtocolFeeUpdate() public {
        uint256 newProtocolFee = PROTOCOL_FEE * 2;
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        prc20Token.updateProtocolFlatFee(newProtocolFee);

        uint256 pcFee = universalCore.withdrawGasFeeInPC(address(prc20Token));

        uint256 expectedGasFee = GAS_PRICE * BASE_GAS_LIMIT + newProtocolFee;
        uint256 expectedPcFee = (expectedGasFee * GAS_TO_PC_RATE) / 1e18;
        assertEq(pcFee, expectedPcFee);
    }

    function test_WithdrawGasFeeInPC_AfterBaseGasLimitUpdate() public {
        uint256 newBaseGasLimit = BASE_GAS_LIMIT * 2;
        vm.prank(deployer);
        universalCore.updateBaseGasLimit(newBaseGasLimit);

        uint256 pcFee = universalCore.withdrawGasFeeInPC(address(prc20Token));

        uint256 expectedGasFee = GAS_PRICE * newBaseGasLimit + PROTOCOL_FEE;
        uint256 expectedPcFee = (expectedGasFee * GAS_TO_PC_RATE) / 1e18;
        assertEq(pcFee, expectedPcFee);
    }

    function test_WithdrawGasFeeInPC_ConsistencyWithGasTokenFee() public view {
        (, uint256 gasFee) = universalCore.withdrawGasFee(address(prc20Token));
        uint256 pcFee = universalCore.withdrawGasFeeInPC(address(prc20Token));

        uint256 expectedPcFee = (gasFee * GAS_TO_PC_RATE) / 1e18;
        assertEq(pcFee, expectedPcFee);
    }

    // ========================================
    // 3) withdrawGasFeeInPCWithGasLimit
    // ========================================

    function test_WithdrawGasFeeInPCWithGasLimit_HappyPath() public view {
        uint256 customGasLimit = 300_000;
        uint256 pcFee = universalCore.withdrawGasFeeInPCWithGasLimit(address(prc20Token), customGasLimit);

        uint256 expectedGasFee = GAS_PRICE * customGasLimit + PROTOCOL_FEE;
        uint256 expectedPcFee = (expectedGasFee * GAS_TO_PC_RATE) / 1e18;
        assertEq(pcFee, expectedPcFee);
    }

    function test_WithdrawGasFeeInPCWithGasLimit_ZeroRate_Reverts() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setGasToPCRate(CHAIN_NAMESPACE, 0);

        vm.expectRevert(UniversalCoreErrors.ZeroGasToPCRate.selector);
        universalCore.withdrawGasFeeInPCWithGasLimit(address(prc20Token), 300_000);
    }

    function test_WithdrawGasFeeInPCWithGasLimit_ZeroGasLimit() public view {
        // gasLimit=0 means fee = protocolFee only (gasPrice * 0 + protocolFee)
        uint256 pcFee = universalCore.withdrawGasFeeInPCWithGasLimit(address(prc20Token), 0);

        uint256 expectedGasFee = PROTOCOL_FEE; // GAS_PRICE * 0 + PROTOCOL_FEE
        uint256 expectedPcFee = (expectedGasFee * GAS_TO_PC_RATE) / 1e18;
        assertEq(pcFee, expectedPcFee);
    }

    function test_WithdrawGasFeeInPCWithGasLimit_MatchesBaseGasLimit() public view {
        uint256 pcFeeDefault = universalCore.withdrawGasFeeInPC(address(prc20Token));
        uint256 pcFeeExplicit = universalCore.withdrawGasFeeInPCWithGasLimit(address(prc20Token), BASE_GAS_LIMIT);

        assertEq(pcFeeDefault, pcFeeExplicit);
    }

    // ========================================
    // 4) Constants & Storage
    // ========================================

    function test_RatePrecision_Is1e18() public view {
        assertEq(universalCore.RATE_PRECISION(), 1e18);
    }

    function test_StorageLayout_Preserved() public view {
        // Existing functionality still works after adding new mapping
        assertEq(universalCore.gasPriceByChainNamespace(CHAIN_NAMESPACE), GAS_PRICE);
        assertEq(universalCore.gasTokenPRC20ByChainNamespace(CHAIN_NAMESPACE), address(mockPRC20));
        assertEq(universalCore.gasToPCRateByChainNamespace(CHAIN_NAMESPACE), GAS_TO_PC_RATE);
        assertEq(universalCore.BASE_GAS_LIMIT(), BASE_GAS_LIMIT);
    }
}
