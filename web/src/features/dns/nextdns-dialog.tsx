// The NextDNS preset of the DNS editor: a configuration ID and, optionally, a device name become the profile's four
// servers (DoH and DoT to NextDNS's two anycast addresses), replacing the list being edited; nothing is saved until the
// editor is.
import { useId, useState } from "react";
import type { DnsServer } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/field";
import { m as ui } from "@/components/ui/messages";
import { useOpenSession } from "@/lib/forms";
import { m } from "./messages";
import { isNextDnsDevice, NEXTDNS_ID, nextDnsName, nextDnsServers } from "./presets";

const TRANSPORT_LABEL: Record<DnsServer["transport"], string> = { udp: "UDP", tcp: "TCP", tls: "DoT", https: "DoH" };

/** What a server is in the preview: `DoH 45.90.28.0:443 · https://dns.nextdns.io/abc123/office-pc`. */
function describe(s: DnsServer): string {
  const via = s.transport === "https" ? ` · ${s.url}` : s.transport === "tls" ? ` · ${s.server_name}` : "";
  return `${TRANSPORT_LABEL[s.transport]} ${s.address}${via}`;
}

export function NextDnsDialog({
  open,
  onOpenChange,
  onApply,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The servers, and the profile name they suggest. */
  onApply: (servers: DnsServer[], name: string) => void;
}) {
  const session = useOpenSession(open);
  return <NextDnsBody key={session} open={open} onOpenChange={onOpenChange} onApply={onApply} />;
}

function NextDnsBody({
  open,
  onOpenChange,
  onApply,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onApply: (servers: DnsServer[], name: string) => void;
}) {
  const formId = useId();
  const [id, setId] = useState("");
  const [device, setDevice] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const cleanId = id.trim().toLowerCase();
  const cleanDevice = device.trim();
  const errors = {
    id: !cleanId ? m.nextDns.errors.idMissing : NEXTDNS_ID.test(cleanId) ? null : m.nextDns.errors.idFormat,
    device: !cleanDevice || isNextDnsDevice(cleanDevice) ? null : m.nextDns.errors.device,
  };
  const valid = !errors.id && !errors.device;
  const show = (message: string | null) => (submitted ? message : null);
  const servers = valid ? nextDnsServers(cleanId, cleanDevice) : null;

  const apply = () => {
    setSubmitted(true);
    if (!servers) return;
    onApply(servers, nextDnsName(cleanId, cleanDevice));
    onOpenChange(false);
  };

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={m.nextDns.title}
      description={m.nextDns.description}
      footer={
        <>
          <Button
            variant="quiet"
            onClick={() => {
              onOpenChange(false);
            }}
          >
            {ui.common.cancel}
          </Button>
          <Button type="submit" form={formId} variant="primary">
            {m.nextDns.apply}
          </Button>
        </>
      }
    >
      <form
        id={formId}
        noValidate
        className="space-y-4"
        onSubmit={(e) => {
          // Rendered in a portal, but inside the editor's form in React: its submit must not reach the editor's.
          e.preventDefault();
          e.stopPropagation();
          apply();
        }}
      >
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label={m.nextDns.id} required hint={m.nextDns.idHint} error={show(errors.id)}>
            {({ id: inputId, describedBy, invalid }) => (
              <Input
                id={inputId}
                mono
                maxLength={6}
                autoComplete="off"
                spellCheck={false}
                placeholder={m.nextDns.idPlaceholder}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={id}
                onChange={(e) => {
                  setId(e.target.value);
                }}
              />
            )}
          </Field>
          <Field label={m.nextDns.device} hint={m.nextDns.deviceHint} error={show(errors.device)}>
            {({ id: inputId, describedBy, invalid }) => (
              <Input
                id={inputId}
                mono
                maxLength={56}
                autoComplete="off"
                spellCheck={false}
                placeholder={m.nextDns.devicePlaceholder}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={device}
                onChange={(e) => {
                  setDevice(e.target.value);
                }}
              />
            )}
          </Field>
        </div>
        <div className="grid grid-cols-1 gap-1.5">
          <p className="text-data font-medium text-fg-secondary">{m.nextDns.servers}</p>
          {servers ? (
            <ol aria-label={m.nextDns.serversLabel} className="grid grid-cols-1 gap-1">
              {servers.map((s, i) => (
                <li key={describe(s)} className="flex gap-2 text-caption">
                  <span aria-hidden className="machine w-4 shrink-0 text-fg-tertiary">
                    {i + 1}
                  </span>
                  <span className="machine min-w-0 text-fg [overflow-wrap:anywhere]">{describe(s)}</span>
                </li>
              ))}
            </ol>
          ) : (
            <p className="text-caption text-fg-tertiary">{m.nextDns.serversLater}</p>
          )}
        </div>
      </form>
    </Dialog>
  );
}
