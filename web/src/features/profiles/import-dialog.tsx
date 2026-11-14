// Import a WireGuard .conf: paste or pick a file → preview (parsed in memory, nothing stored) →
// create. The text holds a private key: it stays in this dialog's memory only — never in the URL,
// browser storage or logs — and is dropped when the dialog closes.

import { ArrowLeft, FileUp, KeyRound } from "lucide-react";
import { type DragEvent, useId, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { useImportProfile } from "@/api/queries";
import type { ImportCandidate, ImportRequest, ProviderKind, ValidationReport } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input, Select, Textarea } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { PropertyGrid, PropertyRow } from "@/components/ui/inspector";
import { m as ui } from "@/components/ui/messages";
import { Callout } from "@/components/ui/states";
import { toast } from "@/components/ui/toast";
import { PROVIDER_NAME } from "@/features/providers/model";
import { localized } from "@/i18n";
import { cn } from "@/lib/cn";
import { useOpenSession } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import { createInstancePath } from "./actions";
import { maskConfig, unmaskConfig } from "./mask";
import { m } from "./messages";

const MAX_CONF_BYTES = 64 * 1024;

/** What the server's check cannot know: how a connection built from this config will behave. */
function usageNotes(c: ImportCandidate | null): { code: string; path: string; message: string }[] {
  if (!c || c.dns.length) return [];
  return [
    {
      code: "NO_DNS",
      path: "/interface/dns",
      message: m.importDialog.noDns,
    },
  ];
}

/** Where in the file an issue is: a line, a setting (`/interface/mtu`), or nothing for the whole file (`/`). */
function issuePlace(path: string): string | null {
  if (path === "/" || path === "") return null;
  const line = /^\/line\/(\d+)$/.exec(path);
  return line ? m.importDialog.line(Number(line[1])) : path;
}

function Issues({ report, candidate }: { report: ValidationReport; candidate: ImportCandidate | null }) {
  const notes = usageNotes(candidate);
  if (!report.issues.length && !notes.length) return <Callout tone="success" title={m.importDialog.checkPassed} />;
  const errors = report.issues.filter((i) => i.severity === "error");
  const warnings = [...report.issues.filter((i) => i.severity === "warning"), ...notes];
  return (
    <div className="space-y-2">
      {errors.length ? (
        <Callout tone="danger" title={m.importDialog.errors(errors.length)}>
          <ul className="list-disc space-y-0.5 pl-4">
            {errors.map((i) => {
              const place = issuePlace(i.path);
              return (
                <li key={`${i.code}${i.path}`}>
                  {place ? <span className="mr-1.5 font-mono text-caption text-fg-tertiary">{place}</span> : null}
                  {localized(i.message)}
                </li>
              );
            })}
          </ul>
        </Callout>
      ) : null}
      {warnings.length ? (
        <Callout tone="warning" title={m.importDialog.warnings(warnings.length)}>
          <ul className="list-disc space-y-0.5 pl-4">
            {warnings.map((i) => (
              <li key={`${i.code}${i.path}`}>{localized(i.message)}</li>
            ))}
          </ul>
        </Callout>
      ) : null}
    </div>
  );
}

/** What the server parsed, before anything is stored: the properties the profile's inspector will show. */
function Candidate({ c }: { c: ImportCandidate }) {
  const list = (xs: string[]) => (xs.length ? m.list(xs) : m.notDeclared);
  return (
    <PropertyGrid>
      <PropertyRow label={m.importDialog.localPublicKey} mono>
        {c.public_key}
      </PropertyRow>
      <PropertyRow label={m.privateKey}>
        <span className="inline-flex items-center gap-1.5">
          <KeyRound aria-hidden className="size-3.5 text-fg-tertiary" />
          {m.importDialog.privateKeyNote}
        </span>
      </PropertyRow>
      <PropertyRow label={m.addresses} mono>
        {list(c.addresses)}
      </PropertyRow>
      <PropertyRow label="DNS" mono>
        {list(c.dns)}
      </PropertyRow>
      <PropertyRow label="MTU" mono>
        {c.mtu}
      </PropertyRow>
      <PropertyRow label={m.importDialog.peerEndpoint} mono>
        {c.endpoint}
      </PropertyRow>
      <PropertyRow label={m.peerPublicKey} mono>
        {c.peer_public_key}
      </PropertyRow>
      <PropertyRow label="AllowedIPs" mono>
        {list(c.allowed_ips)}
      </PropertyRow>
      <PropertyRow label="Keepalive">{c.persistent_keepalive ? m.secs(c.persistent_keepalive) : m.off}</PropertyRow>
      <PropertyRow label={m.presharedKey}>{c.has_preshared_key ? m.presharedStored : m.presharedNone}</PropertyRow>
    </PropertyGrid>
  );
}

export function ImportDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const session = useOpenSession(open);
  return <ImportDialogBody key={session} open={open} onOpenChange={onOpenChange} />;
}

function ImportDialogBody({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const mutation = useImportProfile();
  const intent = useIntentKey("profile.import");
  const navigate = useNavigate();
  const formId = useId();
  const fileRef = useRef<HTMLInputElement>(null);
  const [name, setName] = useState("");
  const [provider, setProvider] = useState<ProviderKind>("generic");
  const [country, setCountry] = useState("");
  const [city, setCity] = useState("");
  const [config, setConfig] = useState("");
  const [preview, setPreview] = useState<{ candidate: ImportCandidate | null; report: ValidationReport } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [fileNote, setFileNote] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);

  // Closing drops the configuration text (the private key) at once; the step and the preview stay
  // as they are while the dialog animates out, and the next opening starts a fresh session. An
  // unknown outcome stays remembered (as a body fingerprint only), so importing the same file
  // again reuses its idempotency key.
  const close = (o: boolean) => {
    if (!o) {
      setConfig("");
      intent.reset();
    }
    onOpenChange(o);
  };

  const request = (mode: ImportRequest["mode"]): ImportRequest => ({
    mode,
    name: name.trim() || m.importDialog.defaultName,
    config,
    provider: provider === "generic" ? null : provider,
    location:
      country.trim() || city.trim()
        ? { country_code: null, country: country.trim() || null, city: city.trim() || null, server: null }
        : null,
  });

  const loadFile = async (file: File | undefined) => {
    if (!file) return;
    if (file.size > MAX_CONF_BYTES) {
      setFileNote(m.importDialog.tooLarge);
      return;
    }
    setConfig(await file.text());
    setPreview(null);
    setFileNote(m.importDialog.fileRead(file.name));
    if (!name.trim()) setName(file.name.replace(/\.conf$/i, ""));
  };

  const run = (mode: ImportRequest["mode"]) => {
    const body = request(mode);
    setError(null);
    mutation.mutate(
      { request: body, key: intent.next(body) },
      {
        onSuccess: (r) => {
          intent.settle();
          if (mode === "preview" || !r.data.profile) {
            setPreview({ candidate: r.data.candidate, report: r.data.report });
            return;
          }
          const created = r.data.profile;
          toast.success(m.importDialog.created(created.name), m.importDialog.createdDetail, {
            label: m.actions.createInstance,
            // The same action as the profile's 建立連線 (its row and its inspector).
            run: () => void navigate(createInstancePath(created)),
          });
          close(false);
          void navigate(`/profiles/${created.id}`);
        },
        onError: (e) => {
          intent.settle(e);
          setError(e);
        },
      },
    );
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    void loadFile(e.dataTransfer.files[0]);
  };

  const step = preview ? "confirm" : "input";
  const canCommit = preview?.report.valid && preview.candidate;
  return (
    <Dialog
      open={open}
      onOpenChange={close}
      width={640}
      title={m.importDialog.title}
      description={step === "input" ? m.importDialog.inputDescription : m.importDialog.confirmDescription}
      footer={
        step === "input" ? (
          <>
            <Button
              variant="quiet"
              onClick={() => {
                close(false);
              }}
            >
              {ui.common.cancel}
            </Button>
            <Button
              type="submit"
              form={formId}
              variant="primary"
              disabled={!config.trim()}
              pending={mutation.isPending}
              pendingLabel={m.importDialog.parsing}
            >
              {m.importDialog.preview}
            </Button>
          </>
        ) : (
          <>
            <Button
              variant="quiet"
              icon={ArrowLeft}
              onClick={() => {
                setPreview(null);
              }}
            >
              {m.importDialog.back}
            </Button>
            <Button
              variant="primary"
              disabled={!canCommit}
              pending={mutation.isPending}
              pendingLabel={ui.common.creating}
              onClick={() => {
                run("commit");
              }}
            >
              {m.importDialog.create}
            </Button>
          </>
        )
      }
    >
      {step === "input" ? (
        <form
          id={formId}
          noValidate
          onSubmit={(e) => {
            e.preventDefault();
            if (config.trim()) run("preview");
          }}
          className="space-y-4"
        >
          <FormFailure error={error} />
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-[minmax(0,1fr)_160px]">
            <Field label={ui.common.name} hint={m.importDialog.nameHint}>
              {({ id, describedBy }) => (
                <Input
                  id={id}
                  aria-describedby={describedBy}
                  maxLength={64}
                  placeholder={m.importDialog.namePlaceholder}
                  value={name}
                  onChange={(e) => {
                    setName(e.target.value);
                  }}
                />
              )}
            </Field>
            <Field label={m.provider}>
              {({ id }) => (
                <Select
                  id={id}
                  value={provider}
                  onChange={(e) => {
                    setProvider(e.target.value as ProviderKind);
                  }}
                >
                  {(Object.keys(PROVIDER_NAME) as ProviderKind[]).map((p) => (
                    <option key={p} value={p}>
                      {PROVIDER_NAME[p]}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label={m.importDialog.country}>
              {({ id }) => (
                <Input
                  id={id}
                  placeholder={m.importDialog.countryPlaceholder}
                  value={country}
                  onChange={(e) => {
                    setCountry(e.target.value);
                  }}
                />
              )}
            </Field>
            <Field label={m.importDialog.city}>
              {({ id }) => (
                <Input
                  id={id}
                  placeholder={m.importDialog.cityPlaceholder}
                  value={city}
                  onChange={(e) => {
                    setCity(e.target.value);
                  }}
                />
              )}
            </Field>
          </div>
          <Field label={m.importDialog.config} required hint={m.importDialog.configHint(fileNote)}>
            {({ id, describedBy }) => (
              // eslint-disable-next-line jsx-a11y/no-static-element-interactions -- a drop zone for a .conf file; the textarea inside is the keyboard path
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => {
                  setDragging(false);
                }}
                onDrop={onDrop}
                className={cn("relative rounded-md", dragging && "ring-2 ring-focus")}
              >
                <Textarea
                  id={id}
                  data-autofocus
                  mono
                  rows={10}
                  aria-describedby={describedBy}
                  spellCheck={false}
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="off"
                  data-1p-ignore
                  data-lpignore="true"
                  placeholder={
                    "[Interface]\nPrivateKey = …\nAddress = 10.64.0.2/32\n\n[Peer]\nPublicKey = …\nEndpoint = 203.0.113.10:51820\nAllowedIPs = 0.0.0.0/0, ::/0"
                  }
                  value={maskConfig(config)}
                  onChange={(e) => {
                    setConfig(unmaskConfig(e.target.value, config));
                    setPreview(null);
                  }}
                  className="resize-y"
                />
              </div>
            )}
          </Field>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
            <input
              ref={fileRef}
              type="file"
              accept=".conf,text/plain"
              className="hidden"
              onChange={(e) => void loadFile(e.target.files?.[0])}
            />
            <Button size="sm" icon={FileUp} onClick={() => fileRef.current?.click()}>
              {m.importDialog.chooseFile}
            </Button>
            <span className="text-caption text-fg-tertiary">{m.importDialog.dropHint}</span>
          </div>
        </form>
      ) : (
        // The preview replaces the form in place: it fades in (no movement), the answer is never delayed.
        <div className="space-y-4 animate-fade-in">
          <FormFailure error={error} />
          {preview ? <Issues report={preview.report} candidate={preview.candidate} /> : null}
          {preview?.candidate ? (
            <div className="rounded-lg border border-line-subtle bg-sunken/60 px-4 py-3">
              <Candidate c={preview.candidate} />
            </div>
          ) : null}
        </div>
      )}
    </Dialog>
  );
}
