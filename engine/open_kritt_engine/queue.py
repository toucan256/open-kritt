import re
from typing import Any

from .models import Job, State, StepResultRow, Workflow
from .prompting import scan_context

WORKFLOW_BUDGET_SCHEMA = "open-kritt.workflow-budget/v1"
WORKFLOW_BUDGET_KEYS = frozenset({"schema", "max_workflow_depth", "max_initial_lineages"})
MAX_WORKFLOW_DEPTH = 64
MAX_INITIAL_LINEAGES = 1_000_000


def _workflow_budget_integer(value, *, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > maximum:
        raise ValueError(f"workflow budget {field} must be an integer between 1 and {maximum}")
    return value


def workflow_budget(scan: dict[str, Any]) -> dict[str, int | str] | None:
    configuration = scan.get("configuration")
    if configuration is None:
        return None
    if not isinstance(configuration, dict):
        raise ValueError("scan configuration must be an object")
    if "workflowBudget" in configuration:
        raise ValueError("scan configuration uses the non-canonical workflow budget key workflowBudget")
    if "workflow_budget" not in configuration:
        return None
    budget = configuration["workflow_budget"]
    if not isinstance(budget, dict):
        raise ValueError("workflow budget must be an object")
    if set(budget) != WORKFLOW_BUDGET_KEYS:
        raise ValueError("workflow budget fields do not match the v1 contract")
    if budget.get("schema") != WORKFLOW_BUDGET_SCHEMA:
        raise ValueError(f"workflow budget schema must be {WORKFLOW_BUDGET_SCHEMA}")

    max_workflow_depth = _workflow_budget_integer(
        budget.get("max_workflow_depth"),
        field="max_workflow_depth",
        maximum=MAX_WORKFLOW_DEPTH,
    )
    max_initial_lineages = _workflow_budget_integer(
        budget.get("max_initial_lineages"),
        field="max_initial_lineages",
        maximum=MAX_INITIAL_LINEAGES,
    )
    job_limit = scan.get("job_limit", scan.get("jobLimit"))
    if job_limit != max_initial_lineages:
        raise ValueError("workflow budget max_initial_lineages must equal the scan job limit")
    jobs_started = scan.get("jobs_started", scan.get("jobsStarted", 0))
    if isinstance(jobs_started, bool) or not isinstance(jobs_started, int) or jobs_started < 0:
        raise ValueError("workflow budget requires a non-negative integer jobs_started counter")
    if jobs_started > max_initial_lineages:
        raise ValueError("workflow budget cumulative jobs_started exceeds max_initial_lineages")
    return {
        "schema": WORKFLOW_BUDGET_SCHEMA,
        "max_workflow_depth": max_workflow_depth,
        "max_initial_lineages": max_initial_lineages,
    }


def repeat_runs(scan: dict[str, Any]) -> int:
    configuration = scan.get("configuration") or {}
    raw = configuration.get("repeat_runs", 1) if isinstance(configuration, dict) else 1
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 1
    return max(1, value)


def metadata_key(step_id: int, state: State):
    return (step_id, state.prev_id, state.prev_table, state.repeat_run)


MULTI_OUTPUT_DEPTH_RE = re.compile(r"^multi_output_depth_\d+$")


def _depth_consumes_all(steps, depth: int) -> bool:
    """A valid workflow applies one consume-all setting to every depth sibling."""

    return depth > 0 and bool(steps) and all(step.consumes_all for step in steps)


def _output_payload(row: StepResultRow) -> dict[str, Any]:
    return row.json_answer if isinstance(row.json_answer, dict) else {}


def _next_states(step, state: State, step_results) -> list[State]:
    if step.is_last_step:
        return []
    next_states = []
    for row in step_results.get(metadata_key(step.id, state), []):
        output = _output_payload(row)
        next_states.append(
            State(
                prev_id=row.id,
                prev_table="workflows.step_results",
                repeat_run=1,
                context={**state.context, **output},
                output=output,
            )
        )
    return next_states


def _batch_state(scan: dict[str, Any], states: list[State], previous_depth: int) -> State:
    """Collapse one repeat run into the context documented as multi_output_depth_N."""

    context = scan_context(scan)
    # Preserve any older batch arrays. Individual output keys from the immediate
    # previous depth intentionally disappear when this depth consumes all.
    for key, value in states[0].context.items():
        if MULTI_OUTPUT_DEPTH_RE.fullmatch(key):
            context[key] = value
    context[f"multi_output_depth_{previous_depth}"] = [state.output or {} for state in states]
    return State(prev_id=0, prev_table=None, repeat_run=1, context=context)


def _state_for_repeat(state: State, repeat_run: int) -> State:
    return State(
        prev_id=state.prev_id,
        prev_table=state.prev_table,
        repeat_run=repeat_run,
        context=state.context,
        output=state.output,
    )


def build_pending_jobs(
    *,
    scan: dict[str, Any],
    workflow: Workflow,
    completed: set[tuple[int, int, str | None, int]],
    step_results: dict[tuple[int, int, str | None, int], list[StepResultRow]],
    claimed: set[tuple[int, int, str | None, int]] | None = None,
    started: set[tuple[int, int, str | None, int]] | None = None,
) -> list[Job]:
    pending: list[Job] = []
    if claimed is None:
        claimed = completed
    if started is None:
        started = claimed
    budget = workflow_budget(scan)
    runs = repeat_runs(scan)
    states = [State(prev_id=0, prev_table=None, repeat_run=1, context=scan_context(scan))]
    previous_depth_complete = True

    for depth in (depth for depth in workflow.depths if budget is None or depth < int(budget["max_workflow_depth"])):
        steps = workflow.steps_at_depth(depth)
        next_states: list[State] = []
        depth_complete = previous_depth_complete

        if _depth_consumes_all(steps, depth):
            # Do not start a batch until every branch in the previous depth has
            # completed. Otherwise a concurrent worker could run it over a
            # partial result set.
            input_states = [_batch_state(scan, states, depth - 1)] if previous_depth_complete and states else []
        else:
            input_states = states

        for state in input_states:
            for step in steps:
                task_complete = True
                task_next_states: list[State] = []
                for repeat_run in range(1, runs + 1):
                    repeated_state = _state_for_repeat(state, repeat_run)
                    key = metadata_key(step.id, repeated_state)
                    if key not in completed:
                        task_complete = False
                        depth_complete = False
                        if key not in claimed:
                            pending.append(Job(step=step, state=repeated_state))
                        # The next repeat needs the output from this one, and the
                        # next depth needs the complete accumulated task output.
                        break
                    task_next_states.extend(_next_states(step, repeated_state, step_results))
                if task_complete:
                    next_states.extend(task_next_states)

        states = next_states
        previous_depth_complete = depth_complete

    ordered_pending = sorted(
        pending,
        key=lambda job: (-job.depth, job.state.repeat_run, job.step.order, job.state.prev_id),
    )
    if budget is None or not ordered_pending:
        return ordered_pending
    jobs_started = int(scan.get("jobs_started", scan.get("jobsStarted", 0)))
    remaining_lineages = int(budget["max_initial_lineages"]) - jobs_started
    retry_pending = [job for job in ordered_pending if metadata_key(job.step.id, job.state) in started]
    new_pending = [job for job in ordered_pending if metadata_key(job.step.id, job.state) not in started]
    if retry_pending:
        return retry_pending + new_pending[:remaining_lineages]
    # Keep one sentinel when exhausted so claim_step_metadata can atomically set
    # job_limit_reached instead of letting the worker treat a truncated workflow
    # as completed and advance to post-processing.
    return new_pending[: max(1, remaining_lineages)]
