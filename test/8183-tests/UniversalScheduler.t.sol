// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

import {UniversalEvalBase} from "./UniversalEvalBase.t.sol";
import {UniversalScheduler} from "../../src/agentic-commerce-8183/UniversalScheduler.sol";
import {UniversalHook} from "../../src/agentic-commerce-8183/hooks/UniversalHook.sol";
import {IAgenticCommerce} from "../../src/agentic-commerce-8183/interfaces/IAgenticCommerce.sol";
import {Recurrence, RECURRING_JOB_PREFIX} from "../../src/agentic-commerce-8183/libraries/JobSpecTypes.sol";

/// @notice A target that records calls, or reverts on demand.
contract SchedTarget {
    uint256 public calls;
    bool public fail;

    function setFail(bool f) external {
        fail = f;
    }

    function ping(uint256 v) external returns (uint256) {
        require(!fail, "target failed");
        ++calls;
        return v + 1;
    }
}

contract UniversalSchedulerTest is Test {
    UniversalScheduler internal sched;
    SchedTarget internal target;
    address internal module = makeAddr("module");
    address internal admin = makeAddr("admin");
    address internal booker = makeAddr("booker");
    address internal stranger = makeAddr("stranger");

    event Executed(uint256 indexed id, bool ok, bytes result);

    function setUp() public {
        vm.warp(1_700_000_000);
        sched = new UniversalScheduler(module, admin);
        target = new SchedTarget();
        vm.prank(admin);
        sched.setBooker(booker, true);
    }

    function _book(uint64 at) internal returns (uint256 id) {
        vm.prank(booker);
        id = sched.schedule(address(target), abi.encodeCall(SchedTarget.ping, (41)), at);
    }

    function test_SC01_constructor_refusesZero() public {
        vm.expectRevert(UniversalScheduler.ZeroAddress.selector);
        new UniversalScheduler(address(0), admin);
        vm.expectRevert(UniversalScheduler.ZeroAddress.selector);
        new UniversalScheduler(module, address(0));
    }

    function test_SC02_schedule_onlyBookers_recordsBooking() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(UniversalScheduler.CallerIsNotBooker.selector, stranger));
        sched.schedule(address(target), "", uint64(block.timestamp));

        uint256 id = _book(uint64(block.timestamp + 10));
        assertEq(id, 0);
        assertEq(sched.bookingCount(), 1);
        UniversalScheduler.Booking memory b = sched.booking(0);
        assertEq(b.target, address(target));
        assertEq(b.executeAt, block.timestamp + 10);
        assertEq(b.booker, booker);
        assertFalse(b.done);
        assertEq(keccak256(b.data), keccak256(abi.encodeCall(SchedTarget.ping, (41))));
        assertEq(_book(0), 1);
    }

    function test_SC03_schedule_refusesZeroTarget() public {
        vm.prank(booker);
        vm.expectRevert(UniversalScheduler.ZeroAddress.selector);
        sched.schedule(address(0), "", 0);
    }

    function test_SC04_execute_onlyModule_onceDue_once() public {
        uint256 id = _book(uint64(block.timestamp + 10));
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(UniversalScheduler.CallerIsNotModule.selector, stranger));
        sched.execute(id);

        vm.prank(module);
        vm.expectRevert(
            abi.encodeWithSelector(UniversalScheduler.NotDue.selector, id, uint64(block.timestamp + 10))
        );
        sched.execute(id);

        vm.warp(block.timestamp + 10);
        vm.prank(module);
        (bool ok, bytes memory ret) = sched.execute(id);
        assertTrue(ok);
        assertEq(abi.decode(ret, (uint256)), 42);
        assertEq(target.calls(), 1);
        assertTrue(sched.booking(id).done);

        vm.prank(module);
        vm.expectRevert(abi.encodeWithSelector(UniversalScheduler.AlreadyExecuted.selector, id));
        sched.execute(id);

        vm.prank(module);
        vm.expectRevert(abi.encodeWithSelector(UniversalScheduler.UnknownBooking.selector, 99));
        sched.execute(99);
    }

    function test_SC05_execute_failingTarget_recordedNotReverted() public {
        uint256 id = _book(uint64(block.timestamp));
        target.setFail(true);
        vm.expectEmit(address(sched));
        emit Executed(id, false, abi.encodeWithSignature("Error(string)", "target failed"));
        vm.prank(module);
        (bool ok,) = sched.execute(id);
        assertFalse(ok);
        assertTrue(sched.booking(id).done, "a failed booking is not run again");
    }

    function test_SC06_due_listsOnlyDueAndUnrun() public {
        _book(uint64(block.timestamp)); // 0 due
        _book(uint64(block.timestamp + 100)); // 1 later
        _book(uint64(block.timestamp)); // 2 due
        _book(uint64(block.timestamp)); // 3 due
        vm.prank(module);
        sched.execute(2);

        uint256[] memory ids = sched.due(0, 10);
        assertEq(ids.length, 2);
        assertEq(ids[0], 0);
        assertEq(ids[1], 3);
        assertEq(sched.due(0, 1).length, 1);
        assertEq(sched.due(1, 10).length, 1);
        assertEq(sched.due(4, 10).length, 0);

        vm.warp(block.timestamp + 100);
        assertEq(sched.due(0, 10).length, 3);
    }

    function test_SC07_admin_setsBookersAndAdmin() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(UniversalScheduler.CallerIsNotAdmin.selector, stranger));
        sched.setBooker(stranger, true);

        vm.prank(admin);
        sched.setBooker(booker, false);
        vm.prank(booker);
        vm.expectRevert(abi.encodeWithSelector(UniversalScheduler.CallerIsNotBooker.selector, booker));
        sched.schedule(address(target), "", 0);

        vm.prank(admin);
        vm.expectRevert(UniversalScheduler.ZeroAddress.selector);
        sched.setAdmin(address(0));
        vm.prank(admin);
        sched.setAdmin(stranger);
        assertEq(sched.admin(), stranger);
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(UniversalScheduler.CallerIsNotAdmin.selector, admin));
        sched.setBooker(booker, true);
    }

    function testFuzz_SC08_execute_neverBeforeDue(uint64 at, uint64 now_) public {
        vm.assume(now_ > 0);
        vm.warp(now_);
        uint256 id = _book(at);
        vm.prank(module);
        if (now_ < at) {
            vm.expectRevert(abi.encodeWithSelector(UniversalScheduler.NotDue.selector, id, at));
            sched.execute(id);
        } else {
            (bool ok,) = sched.execute(id);
            assertTrue(ok);
        }
    }
}

/// @notice The hook and the real scheduler together, the test playing the chain module.
contract UniversalSchedulerSeriesTest is UniversalEvalBase {
    UniversalScheduler internal sched;
    address internal module = makeAddr("schedulerModule");
    uint32 internal constant PERIOD = 1 days;
    uint256 internal t0; // in storage: under via-IR a local `block.timestamp` can be re-read after `vm.warp`

    function setUp() public override {
        super.setUp();
        t0 = block.timestamp;
        sched = new UniversalScheduler(module, admin);
        vm.prank(admin);
        sched.setBooker(address(hook), true);
        address impl = address(uint160(uint256(vm.load(address(hook), ERC1967Utils.IMPLEMENTATION_SLOT))));
        address proxyAdmin = address(uint160(uint256(vm.load(address(hook), ERC1967Utils.ADMIN_SLOT))));
        vm.prank(proxyAdminOwner);
        ProxyAdmin(proxyAdmin).upgradeAndCall(
            ITransparentUpgradeableProxy(address(hook)), impl, abi.encodeCall(UniversalHook.setScheduler, (address(sched)))
        );
        vm.prank(owner);
        agw.setRenewer(address(hook));
    }

    function test_SS01_twoPeriodSeries_throughTheScheduler() public {
        Recurrence memory r = Recurrence(uint64(t0), PERIOD, 2, 0, BUDGET);
        bytes memory d = abi.encodePacked(RECURRING_JOB_PREFIX, abi.encode(_swapSpec(), r));
        vm.prank(owner);
        agw.execute(
            address(kernel),
            0,
            abi.encodeCall(kernel.createJob, (provider, address(ue), t0 + 12 hours, string(d), address(hook)))
        );
        uint256 id = kernel.jobCounter();
        vm.prank(provider);
        kernel.setBudget(id, BUDGET, "");
        _fund(id);
        assertEq(sched.bookingCount(), 2);
        assertEq(sched.due(0, 10).length, 0, "nothing due yet");

        _answerSnapshot(id, SWAP_PRE, 0);
        _advance();
        _submit(id);
        _answer(id, 0, abi.encode(uint256(0.4e18)));

        vm.warp(t0 + PERIOD);
        uint256[] memory ids = sched.due(0, 10);
        assertEq(ids.length, 1);
        vm.prank(module);
        (bool ok,) = sched.execute(ids[0]);
        assertTrue(ok);
        uint256 job = hook.seriesOf(id).pendingJob;
        assertGt(job, id);
        vm.prank(provider);
        kernel.setBudget(job, BUDGET, "");

        vm.warp(t0 + PERIOD + hook.FUND_DELAY());
        _advance();
        ids = sched.due(0, 10);
        assertEq(ids.length, 1);
        vm.prank(module);
        (ok,) = sched.execute(ids[0]);
        assertTrue(ok);

        assertEq(uint8(kernel.getJob(job).status), uint8(IAgenticCommerce.JobStatus.Funded));
        assertEq(uint8(hook.seriesOf(id).status), uint8(UniversalHook.SeriesStatus.Ended));
        assertEq(sched.bookingCount(), 2, "last period books nothing");
        assertEq(sched.due(0, 10).length, 0);
    }

    /// @notice The hook isn't an allowed booker: opening the series fails, so `fund` reverts and nothing moves.
    function test_SS02_hookNotBooker_fundReverts() public {
        vm.prank(admin);
        sched.setBooker(address(hook), false);
        bytes memory d =
            abi.encodePacked(RECURRING_JOB_PREFIX, abi.encode(_swapSpec(), Recurrence(uint64(t0), PERIOD, 2, 0, BUDGET)));
        vm.prank(owner);
        agw.execute(
            address(kernel),
            0,
            abi.encodeCall(kernel.createJob, (provider, address(ue), t0 + 12 hours, string(d), address(hook)))
        );
        uint256 id = kernel.jobCounter();
        vm.prank(provider);
        kernel.setBudget(id, BUDGET, "");
        (uint256 s, uint256 e) = ue.prefundCost(id);
        _prefund(id, s + e);
        bytes memory params = _fundParams(id);
        vm.expectRevert(abi.encodeWithSelector(UniversalScheduler.CallerIsNotBooker.selector, address(hook)));
        _fundWith(id, params);
        assertEq(uint8(kernel.getJob(id).status), uint8(IAgenticCommerce.JobStatus.Open));
    }
}
