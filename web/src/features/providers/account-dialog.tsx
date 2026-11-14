// Add a provider account. The credential lives only in this dialog's memory until the server has
// verified it (over the Provider egress) and put it in the vault; it is never shown again. With
// no egress yet, the first setup may open the direct bootstrap — only after the user allows it.

import { Eye, EyeOff, KeyRound } from "lucide-react";
import { useId, useState } from "react";
import { useNavigate } from "react-router";
import { newIdempotencyKey } from "@/api/client";
import { useCreateProviderAccount, useOpenBootstrap, useProviderEgress } from "@/api/queries";
import type { ProviderAccountInput } from "@/api/types";
import { ActionButton } from "@/components/ui/action-button";
import { Button, IconButton } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { m as ui } from "@/components/ui/messages";
import { Segmented } from "@/components/ui/segmented";
import { Callout } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { serverFieldErrors, useOpenSession } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import { m } from "./messages";
import { PROVIDER_NAME } from "./model";

type Kind = "mullvad" | "airvpn";

/** Mullvad prints account numbers in groups of four; digits are what counts. */
function formatNumber(raw: string): string {
  return raw
    .replace(/\D/g, "")
    .slice(0, 16)
    .replace(/(\d{4})(?=\d)/g, "$1 ");
}

export function AccountDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const session = useOpenSession(open);
  return <AccountDialogBody key={session} open={open} onOpenChange={onOpenChange} />;
}

function AccountDialogBody({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const create = useCreateProviderAccount();
  const bootstrap = useOpenBootstrap();
  const egress = useProviderEgress();
  const intent = useIntentKey("provider_account.create");
  const navigate = useNavigate();
  const formId = useId();
  const [kind, setKind] = useState<Kind>("mullvad");
  const [label, setLabel] = useState("");
  const [number, setNumber] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [reveal, setReveal] = useState(false);
  const [allowDirect, setAllowDirect] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<unknown>(null);

  // Closing drops the credential at once; the emptied fields are not re-validated while the
  // dialog animates out (the next opening starts a fresh session).
  const close = (o: boolean) => {
    if (!o) {
      setNumber("");
      setPassword("");
      setUsername("");
      setSubmitted(false);
      intent.reset();
    }
    onOpenChange(o);
  };

  const phase = egress.data?.phase;
  const firstSetup = phase === "unconfigured" && egress.data?.bootstrap_consumed === false;
  const egressMissing = phase === "unconfigured" || phase === "disabled" || phase === "blocked";
  const digits = number.replace(/\D/g, "");
  const errors: Record<string, string> = {};
  if (kind === "mullvad" && digits.length !== 16) errors.number = m.add.errors.accountNumber;
  if (kind === "airvpn" && !username.trim()) errors.username = m.add.errors.username;
  if (kind === "airvpn" && !password) errors.password = m.add.errors.password;
  if (firstSetup && !allowDirect) errors.direct = m.add.errors.direct;
  const server = serverFieldErrors(error);
  const shown = (k: string, path: string) =>
    submitted ? (errors[k] ?? server.get(path) ?? null) : (server.get(path) ?? null);
  const ready = Object.keys(errors).length === 0 && !(egressMissing && !firstSetup);

  const submit = async () => {
    setSubmitted(true);
    if (!ready) return;
    setError(null);
    const input: ProviderAccountInput = {
      label: label.trim() || m.account.defaultLabel(PROVIDER_NAME[kind]),
      credential:
        kind === "mullvad"
          ? { provider: "mullvad", account_number: digits }
          : { provider: "airvpn", username: username.trim(), password },
    };
    try {
      if (firstSetup) await bootstrap.mutateAsync({ key: newIdempotencyKey() });
    } catch (e) {
      setError(e);
      return;
    }
    // The fingerprint of the body is all the intent key keeps (never the credential).
    create.mutate(
      { input, key: intent.next(input) },
      {
        onSuccess: (r) => {
          intent.settle();
          toast.success(m.add.added(r.data.label), m.add.addedDetail);
          close(false);
          void navigate(`/providers/${r.data.id}`);
        },
        onError: (e) => {
          intent.settle(e);
          setError(e);
        },
      },
    );
  };

  const pending = create.isPending || bootstrap.isPending;
  return (
    <Dialog
      open={open}
      onOpenChange={close}
      width={560}
      title={m.add.title}
      description={m.add.description}
      footer={
        <>
          <Button
            variant="quiet"
            onClick={() => {
              close(false);
            }}
          >
            {ui.common.cancel}
          </Button>
          <ActionButton
            type="submit"
            form={formId}
            variant="primary"
            disabledReason={egressMissing && !firstSetup ? m.add.noEgressReason : null}
            pending={pending}
            pendingLabel={m.add.verifying}
          >
            {m.add.submit}
          </ActionButton>
        </>
      }
    >
      <form
        id={formId}
        noValidate
        autoComplete="off"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
        className="space-y-4"
      >
        <FormFailure error={error} />
        {egressMissing && !firstSetup ? (
          <Callout tone="danger" title={m.egressNeeded.none}>
            {m.add.noEgressHint}
          </Callout>
        ) : null}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <Segmented
            label={m.add.provider}
            value={kind}
            onChange={(v) => {
              setKind(v);
              setSubmitted(false);
            }}
            options={[
              { value: "mullvad", label: "Mullvad" },
              { value: "airvpn", label: "AirVPN" },
            ]}
          />
          <span className="inline-flex items-center gap-1.5 text-caption text-fg-tertiary">
            <KeyRound aria-hidden className="size-3.5" />
            {m.add.storedEncrypted}
          </span>
        </div>
        <Field label={ui.common.name} hint={m.add.nameHint}>
          {({ id, describedBy }) => (
            <Input
              id={id}
              aria-describedby={describedBy}
              maxLength={64}
              placeholder={m.account.defaultLabel(PROVIDER_NAME[kind])}
              value={label}
              onChange={(e) => {
                setLabel(e.target.value);
              }}
            />
          )}
        </Field>
        {kind === "mullvad" ? (
          <Field
            label={m.add.accountNumber}
            required
            error={shown("number", "/credential/account_number")}
            hint={m.add.accountNumberHint}
          >
            {({ id, describedBy, invalid }) => (
              <div className="relative">
                <Input
                  id={id}
                  data-autofocus
                  mono
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  type={reveal ? "text" : "password"}
                  inputMode="numeric"
                  autoComplete="off"
                  spellCheck={false}
                  data-1p-ignore
                  data-lpignore="true"
                  placeholder="0000 0000 0000 0000"
                  value={reveal ? number : digits}
                  onChange={(e) => {
                    setNumber(formatNumber(e.target.value));
                  }}
                  className="pr-10 tracking-wider"
                />
                <IconButton
                  label={reveal ? m.add.hideAccountNumber : m.add.showAccountNumber}
                  icon={reveal ? EyeOff : Eye}
                  className="absolute right-1 top-1/2 -translate-y-1/2"
                  onClick={() => {
                    setReveal((r) => !r);
                  }}
                />
              </div>
            )}
          </Field>
        ) : (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label={m.add.username} required error={shown("username", "/credential/username")}>
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  data-autofocus
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  autoComplete="off"
                  spellCheck={false}
                  data-1p-ignore
                  data-lpignore="true"
                  value={username}
                  onChange={(e) => {
                    setUsername(e.target.value);
                  }}
                />
              )}
            </Field>
            <Field label={m.add.password} required error={shown("password", "/credential/password")}>
              {({ id, describedBy, invalid }) => (
                <Input
                  id={id}
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  type="password"
                  autoComplete="off"
                  data-1p-ignore
                  data-lpignore="true"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                  }}
                />
              )}
            </Field>
          </div>
        )}
        {kind === "airvpn" ? <p className="text-caption text-fg-tertiary">{m.add.airvpnDevices}</p> : null}
        {firstSetup ? (
          <Callout tone="warning" title={m.add.firstSetup}>
            <p>{m.add.firstSetupHint}</p>
            <label className="mt-2 flex cursor-pointer items-center gap-2 text-data text-fg">
              <input
                type="checkbox"
                className="size-4 shrink-0 accent-action"
                checked={allowDirect}
                onChange={(e) => {
                  setAllowDirect(e.target.checked);
                }}
              />
              {m.add.allowDirect}
            </label>
            {submitted && errors.direct ? (
              <p role="alert" className="mt-1 text-caption text-danger animate-reveal">
                {errors.direct}
              </p>
            ) : null}
          </Callout>
        ) : null}
      </form>
    </Dialog>
  );
}
