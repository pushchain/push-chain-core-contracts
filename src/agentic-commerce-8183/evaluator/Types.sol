// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title Types — the evaluator's spec types, at the path the UniversalHook imports them from
/// @dev Re-exports the one definition in `libraries/JobSpecTypes.sol` (the wire format the marketplace builds),
///      so there is never a second `JobSpec`. Nothing here uses them; importers do.
// forge-lint: disable-next-line(unused-import)
import {JobSpec, Mutability} from "../libraries/JobSpecTypes.sol";
