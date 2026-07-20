// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../../src/UniversalCore.sol";
import "../../src/interfaces/IUniversalCore.sol";
import {UniversalCoreErrors, CommonErrors} from "../../src/libraries/Errors.sol";
import "../../test/helpers/UpgradeableContractHelper.sol";
import {
    IAccessControlDefaultAdminRules
} from "@openzeppelin/contracts/access/extensions/IAccessControlDefaultAdminRules.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import "../../test/mocks/MockUniswapV3Factory.sol";
import "../../test/mocks/MockUniswapV3Router.sol";
import "../../test/mocks/MockWPC.sol";

contract UniversalCorePC20Test is Test, UpgradeableContractHelper {
    UniversalCore public universalCore;
    MockUniswapV3Factory public mockFactory;
    MockUniswapV3Router public mockRouter;
    MockWPC public mockWPC;

    address public constant UNIVERSAL_EXECUTOR_MODULE = 0x14191Ea54B4c176fCf86f51b0FAc7CB1E71Df7d7;

    address public deployer;
    address public nonUEModule;
    address public nonOperator;
    address public pauser;
    address public pc20TokenA;
    address public pc20TokenB;

    string public constant CHAIN_A = "eip155:1";
    string public constant CHAIN_B = "eip155:137";
    uint256 public constant BASE_GAS_LIMIT = 500_000;
    uint256 public constant GAS_PRICE = 50 * 10 ** 9;
    uint256 public constant DEPLOY_OVERHEAD = 1_000_000;

    address public wrapperAAddr;
    address public wrapperBAddr;
    bytes32 public wrapperA;
    bytes32 public wrapperB;

    event SetPC20Deployed(address indexed sourceAsset, string destChain, bytes32 wrapper);
    event SetPC20FactoryByChain(string chainNamespace, bytes32 factory);

    function setUp() public {
        deployer = address(this);
        nonUEModule = makeAddr("nonUEModule");
        nonOperator = makeAddr("nonOperator");
        pauser = makeAddr("pauser");
        pc20TokenA = makeAddr("pc20TokenA");
        pc20TokenB = makeAddr("pc20TokenB");
        wrapperAAddr = makeAddr("wrapperA");
        wrapperBAddr = makeAddr("wrapperB");
        wrapperA = bytes32(uint256(uint160(wrapperAAddr)));
        wrapperB = bytes32(uint256(uint160(wrapperBAddr)));

        mockFactory = new MockUniswapV3Factory();
        mockRouter = new MockUniswapV3Router();
        mockWPC = new MockWPC();

        UniversalCore implementation = new UniversalCore();

        bytes memory initData = abi.encodeWithSelector(
            UniversalCore.initialize.selector,
            deployer,
            pauser,
            address(mockWPC),
            address(mockFactory),
            address(mockRouter)
        );

        address proxyAddress = deployUpgradeableContract(address(implementation), initData);
        universalCore = UniversalCore(payable(proxyAddress));

        // Grant UVCORE_ADMIN_ROLE to UE Module (called by deployer with ROLE_MANAGER_ROLE)
        universalCore.grantRole(universalCore.UVCORE_ADMIN_ROLE(), UNIVERSAL_EXECUTOR_MODULE);

        // Configure both chains via UEM
        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);

        // Chain A setup
        universalCore.updateGasTokenPRC20(CHAIN_A, address(0x1));
        universalCore.setChainMeta(CHAIN_A, GAS_PRICE, 0);
        universalCore.updateBaseGasLimitByChain(CHAIN_A, BASE_GAS_LIMIT);

        // Chain B setup
        universalCore.updateGasTokenPRC20(CHAIN_B, address(0x2));
        universalCore.setChainMeta(CHAIN_B, GAS_PRICE, 0);
        universalCore.updateBaseGasLimitByChain(CHAIN_B, BASE_GAS_LIMIT);

        universalCore.updatePC20DeploymentGasOverhead(CHAIN_A, DEPLOY_OVERHEAD);
        universalCore.updatePC20DeploymentGasOverhead(CHAIN_B, DEPLOY_OVERHEAD);
        vm.stopPrank();
    }

    // ========================================
    //  getPC20ExportGasAndFees — Deploy Flag
    // ========================================

    function test_GetPC20ExportGasAndFees_FirstExportAddsOverhead() public view {
        (,,,,, uint256 gasLimitUsed, bool isFirstExport) = universalCore.getPC20ExportGasAndFees(CHAIN_A, 0, pc20TokenA);

        assertEq(gasLimitUsed, BASE_GAS_LIMIT + DEPLOY_OVERHEAD);
        assertTrue(isFirstExport);
    }

    function test_GetPC20ExportGasAndFees_AfterDeployFlagSkipsOverhead() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);

        (,,,,, uint256 gasLimitUsed, bool isFirstExport) = universalCore.getPC20ExportGasAndFees(CHAIN_A, 0, pc20TokenA);

        assertEq(gasLimitUsed, BASE_GAS_LIMIT);
        assertFalse(isFirstExport);
    }

    function test_GetPC20ExportGasAndFees_MultiChainIndependent() public {
        // Deploy on chain A only
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);

        // Chain A: no overhead
        (,,,,, uint256 gasLimitA, bool isFirstA) = universalCore.getPC20ExportGasAndFees(CHAIN_A, 0, pc20TokenA);
        assertEq(gasLimitA, BASE_GAS_LIMIT);
        assertFalse(isFirstA);

        // Chain B: still overhead
        (,,,,, uint256 gasLimitB, bool isFirstB) = universalCore.getPC20ExportGasAndFees(CHAIN_B, 0, pc20TokenA);
        assertEq(gasLimitB, BASE_GAS_LIMIT + DEPLOY_OVERHEAD);
        assertTrue(isFirstB);
    }

    function test_GetPC20ExportGasAndFees_DifferentTokensIndependent() public {
        // Deploy token A on chain A
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);

        // Token A: no overhead
        (,,,,, uint256 gasLimitA, bool isFirstA) = universalCore.getPC20ExportGasAndFees(CHAIN_A, 0, pc20TokenA);
        assertEq(gasLimitA, BASE_GAS_LIMIT);
        assertFalse(isFirstA);

        // Token B: still overhead
        (,,,,, uint256 gasLimitB, bool isFirstB) = universalCore.getPC20ExportGasAndFees(CHAIN_A, 0, pc20TokenB);
        assertEq(gasLimitB, BASE_GAS_LIMIT + DEPLOY_OVERHEAD);
        assertTrue(isFirstB);
    }

    function test_GetPC20ExportGasAndFees_CustomGasLimitWithDeployFlag() public {
        uint256 customLimit = 800_000;

        // First export: overhead added to custom limit
        (,,,,, uint256 gasLimitFirst,) = universalCore.getPC20ExportGasAndFees(CHAIN_A, customLimit, pc20TokenA);
        assertEq(gasLimitFirst, customLimit + DEPLOY_OVERHEAD);

        // After deploy: no overhead
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);

        (,,,,, uint256 gasLimitSecond,) = universalCore.getPC20ExportGasAndFees(CHAIN_A, customLimit, pc20TokenA);
        assertEq(gasLimitSecond, customLimit);
    }

    function test_GetPC20ExportGasAndFees_NoOverheadConfigured() public {
        // Configure a chain with gas settings but no deployment overhead
        string memory chainNoOverhead = "eip155:999";
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.updateGasTokenPRC20(chainNoOverhead, address(0x3));
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setChainMeta(chainNoOverhead, GAS_PRICE, 0);
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.updateBaseGasLimitByChain(chainNoOverhead, BASE_GAS_LIMIT);

        // No pc20DeploymentGasOverhead set — should be 0 by default
        (,,,,, uint256 gasLimitUsed, bool isFirstExport) =
            universalCore.getPC20ExportGasAndFees(chainNoOverhead, 0, pc20TokenA);

        assertEq(gasLimitUsed, BASE_GAS_LIMIT);
        assertFalse(isFirstExport);
    }

    // ========================================
    //  setWrapperDeployed
    // ========================================

    function test_SetWrapperDeployed_OnlyUEModule() public {
        vm.prank(nonUEModule);
        vm.expectRevert(abi.encodeWithSelector(UniversalCoreErrors.CallerIsNotUEModule.selector));
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);
    }

    function test_SetWrapperDeployed_SetsFlag() public {
        assertFalse(universalCore.pc20Deployed(pc20TokenA, CHAIN_A));

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);

        assertTrue(universalCore.pc20Deployed(pc20TokenA, CHAIN_A));
    }

    function test_SetWrapperDeployed_EmitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit SetPC20Deployed(pc20TokenA, CHAIN_A, wrapperA);

        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);
    }

    function test_SetWrapperDeployed_Idempotent() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);

        // Second call should not emit event (no-op)
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);

        assertTrue(universalCore.pc20Deployed(pc20TokenA, CHAIN_A));
    }

    function test_SetWrapperDeployed_MultiChain() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);

        assertTrue(universalCore.pc20Deployed(pc20TokenA, CHAIN_A));
        assertFalse(universalCore.pc20Deployed(pc20TokenA, CHAIN_B));
        assertFalse(universalCore.pc20Deployed(pc20TokenB, CHAIN_A));
    }

    // ========================================
    //  updatePC20FactoryByChain
    // ========================================

    function _toBytes32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function test_UpdatePC20FactoryByChain_OnlyOperator() public {
        bytes32 factory = _toBytes32(makeAddr("factory"));

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, nonOperator, universalCore.OPERATOR_ROLE()
            )
        );
        vm.prank(nonOperator);
        universalCore.updatePC20FactoryByChain(CHAIN_A, factory);
    }

    function test_UpdatePC20FactoryByChain_SetsAddress() public {
        bytes32 factory = _toBytes32(makeAddr("factory"));
        assertEq(universalCore.pc20FactoryByChain(CHAIN_A), bytes32(0));

        universalCore.updatePC20FactoryByChain(CHAIN_A, factory);

        assertEq(universalCore.pc20FactoryByChain(CHAIN_A), factory);
    }

    function test_UpdatePC20FactoryByChain_EmitsEvent() public {
        bytes32 factory = _toBytes32(makeAddr("factory"));

        vm.expectEmit(true, true, false, true);
        emit SetPC20FactoryByChain(CHAIN_A, factory);

        universalCore.updatePC20FactoryByChain(CHAIN_A, factory);
    }

    function test_UpdatePC20FactoryByChain_Overwrites() public {
        bytes32 factoryA = _toBytes32(makeAddr("factoryA"));
        bytes32 factoryB = _toBytes32(makeAddr("factoryB"));

        universalCore.updatePC20FactoryByChain(CHAIN_A, factoryA);
        assertEq(universalCore.pc20FactoryByChain(CHAIN_A), factoryA);

        universalCore.updatePC20FactoryByChain(CHAIN_A, factoryB);
        assertEq(universalCore.pc20FactoryByChain(CHAIN_A), factoryB);
    }

    function test_UpdatePC20FactoryByChain_IndependentChains() public {
        bytes32 factoryA = _toBytes32(makeAddr("factoryA"));
        bytes32 factoryB = _toBytes32(makeAddr("factoryB"));

        universalCore.updatePC20FactoryByChain(CHAIN_A, factoryA);
        universalCore.updatePC20FactoryByChain(CHAIN_B, factoryB);

        assertEq(universalCore.pc20FactoryByChain(CHAIN_A), factoryA);
        assertEq(universalCore.pc20FactoryByChain(CHAIN_B), factoryB);
    }

    // ========================================
    //  getPC20Wrapper
    // ========================================

    function test_GetPC20Wrapper_BeforeDeploy() public view {
        (bytes32 wrapper, bool deployed) = universalCore.getPC20Wrapper(pc20TokenA, CHAIN_A);
        assertEq(wrapper, bytes32(0));
        assertFalse(deployed);
    }

    function test_GetPC20Wrapper_AfterDeploy() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);

        (bytes32 wrapper, bool deployed) = universalCore.getPC20Wrapper(pc20TokenA, CHAIN_A);
        assertEq(wrapper, wrapperA);
        assertTrue(deployed);
    }

    function test_GetPC20Wrapper_CrossChainIndependent() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);

        (bytes32 wA, bool dA) = universalCore.getPC20Wrapper(pc20TokenA, CHAIN_A);
        (bytes32 wB, bool dB) = universalCore.getPC20Wrapper(pc20TokenA, CHAIN_B);

        assertEq(wA, wrapperA);
        assertTrue(dA);
        assertEq(wB, bytes32(0));
        assertFalse(dB);
    }

    // ========================================
    //  getPC20Source
    // ========================================

    function test_GetPC20Source_BeforeDeploy() public view {
        (address source, bool known) = universalCore.getPC20Source(wrapperA, CHAIN_A);
        assertEq(source, address(0));
        assertFalse(known);
    }

    function test_GetPC20Source_AfterDeploy() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);

        (address source, bool known) = universalCore.getPC20Source(wrapperA, CHAIN_A);
        assertEq(source, pc20TokenA);
        assertTrue(known);
    }

    function test_GetPC20Source_UnknownWrapper() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);

        (address source, bool known) = universalCore.getPC20Source(wrapperB, CHAIN_A);
        assertEq(source, address(0));
        assertFalse(known);
    }

    // ========================================
    //  Mapping Consistency
    // ========================================

    function test_SetWrapperDeployed_BidirectionalMapping() public {
        vm.prank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);

        assertEq(universalCore.pc20WrapperBySource(pc20TokenA, CHAIN_A), wrapperA);
        assertEq(universalCore.pc20SourceByWrapper(CHAIN_A, wrapperA), pc20TokenA);
    }

    function test_SetWrapperDeployed_MultipleTokensSameChain() public {
        vm.startPrank(UNIVERSAL_EXECUTOR_MODULE);
        universalCore.setWrapperDeployed(pc20TokenA, CHAIN_A, wrapperA);
        universalCore.setWrapperDeployed(pc20TokenB, CHAIN_A, wrapperB);
        vm.stopPrank();

        assertEq(universalCore.pc20WrapperBySource(pc20TokenA, CHAIN_A), wrapperA);
        assertEq(universalCore.pc20WrapperBySource(pc20TokenB, CHAIN_A), wrapperB);
        assertEq(universalCore.pc20SourceByWrapper(CHAIN_A, wrapperA), pc20TokenA);
        assertEq(universalCore.pc20SourceByWrapper(CHAIN_A, wrapperB), pc20TokenB);
    }
}
