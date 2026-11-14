import { ApiFailure } from "@/api/client";
import { Button } from "./button";
import { m } from "./messages";
import { Callout } from "./states";

/**
 * The non-field outcome of a failed submit, in place. Field messages render at their fields; a
 * revision conflict offers reload or overwrite; an unknown outcome explains why resubmitting the
 * same content is safe (the same idempotency key is reused).
 */
export function FormFailure({
  error,
  onReload,
  onOverwrite,
  pending,
}: {
  error: unknown;
  onReload?: (() => void) | undefined;
  onOverwrite?: (() => void) | undefined;
  pending?: boolean | undefined;
}) {
  if (!error) return null;
  if (error instanceof ApiFailure) {
    if (error.kind === "unknown_outcome") {
      return (
        <Callout tone="warning" title={m.formFailure.unknownOutcome}>
          {m.formFailure.unknownOutcomeDetail}
        </Callout>
      );
    }
    if (error.code === "REVISION_CONFLICT") {
      return (
        <Callout
          tone="warning"
          title={m.formFailure.conflict}
          actions={
            <>
              {onReload ? (
                <Button size="sm" onClick={onReload} disabled={pending}>
                  {m.formFailure.reload}
                </Button>
              ) : null}
              {onOverwrite ? (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={onOverwrite}
                  pending={pending}
                  pendingLabel={m.formFailure.overwriting}
                >
                  {m.formFailure.overwrite}
                </Button>
              ) : null}
            </>
          }
        >
          {m.formFailure.conflictDetail}
        </Callout>
      );
    }
    if (error.code === "VALIDATION_FAILED" && error.fieldErrors().size > 0) {
      return <Callout tone="danger" title={m.formFailure.fixFields} />;
    }
  }
  return (
    <Callout tone="danger" title={m.formFailure.notCompleted}>
      {error instanceof Error ? error.message : m.unexpectedError}
    </Callout>
  );
}
