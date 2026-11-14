// Editing a WireGuard profile: its name, the place it is shown under, MTU and keepalive. Keys, the endpoint and the
// addresses come from the imported configuration and are not edited here. A save the worker uses offers to restart the
// running connections that still use the previous version (announceSaved).
import { useId, useState } from "react";
import { apiGet } from "@/api/client";
import { useUpdateProfile } from "@/api/queries";
import type { ProfileUpdate, RuntimeProfile } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { m as ui } from "@/components/ui/messages";
import { announceSaved } from "@/features/instances/actions";
import { workerInput } from "@/features/instances/worker-input";
import { parseIntField, serverFieldErrors, useOpenSession } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import { m } from "./messages";

export function EditProfileDialog({
  profile,
  open,
  onOpenChange,
}: {
  profile: RuntimeProfile;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const session = useOpenSession(open);
  return <EditProfileBody key={session} profile={profile} open={open} onOpenChange={onOpenChange} />;
}

function EditProfileBody({
  profile,
  open,
  onOpenChange,
}: {
  profile: RuntimeProfile;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const update = useUpdateProfile();
  const intent = useIntentKey(`profile.update:${profile.id}`);
  const formId = useId();
  const [name, setName] = useState(profile.name);
  const [country, setCountry] = useState(profile.location?.country ?? "");
  const [city, setCity] = useState(profile.location?.city ?? "");
  const [server, setServer] = useState(profile.location?.server ?? "");
  const [mtu, setMtu] = useState(String(profile.interface.mtu));
  const [keepalive, setKeepalive] = useState(String(profile.peer.persistent_keepalive ?? 0));
  const [revision, setRevision] = useState(profile.revision);
  // What the worker takes from the version these fields were loaded from (name and location are not part of it).
  const [loaded, setLoaded] = useState({
    revision: profile.revision,
    worker: workerInput.profile(profile.interface.mtu, profile.peer.persistent_keepalive),
  });
  const [error, setError] = useState<unknown>(null);
  const [submitted, setSubmitted] = useState(false);

  const server_ = serverFieldErrors(error);
  const mtuN = parseIntField(mtu);
  const kaN = parseIntField(keepalive);
  const errors = {
    name: !name.trim() ? ui.common.enterName : (server_.get("/name") ?? null),
    mtu: mtuN === null || mtuN < 576 || mtuN > 9000 ? "576–9000" : (server_.get("/interface/mtu") ?? null),
    keepalive: kaN === null || kaN > 65535 ? m.edit.keepaliveRange : null,
  };
  const valid = !errors.name && !errors.mtu && !errors.keepalive;
  const show = (m: string | null) => (submitted || error ? m : null);

  const submit = (rev = revision) => {
    setSubmitted(true);
    if (!valid || mtuN === null || kaN === null) return;
    const input: ProfileUpdate = {
      name: name.trim(),
      location:
        country.trim() || city.trim() || server.trim()
          ? {
              country_code: profile.location?.country_code ?? null,
              country: country.trim() || null,
              city: city.trim() || null,
              server: server.trim() || null,
            }
          : null,
      mtu: mtuN,
      persistent_keepalive: kaN,
    };
    const workerChanged =
      rev !== loaded.revision || loaded.worker !== workerInput.profile(input.mtu, input.persistent_keepalive);
    setError(null);
    update.mutate(
      { id: profile.id, revision: rev, input, key: intent.next({ rev, input }) },
      {
        onSuccess: (r) => {
          intent.settle();
          announceSaved({
            title: m.edit.updated(input.name),
            kind: "profile",
            id: profile.id,
            revision: r.data.revision,
            workerChanged,
          });
          onOpenChange(false);
        },
        onError: (e) => {
          intent.settle(e);
          setError(e);
        },
      },
    );
  };

  const latest = async (apply: boolean) => {
    try {
      const p = await apiGet<RuntimeProfile>(`/v1/profiles/${profile.id}`);
      setRevision(p.revision);
      if (apply) {
        setLoaded({ revision: p.revision, worker: workerInput.profile(p.interface.mtu, p.peer.persistent_keepalive) });
        setName(p.name);
        setCountry(p.location?.country ?? "");
        setCity(p.location?.city ?? "");
        setServer(p.location?.server ?? "");
        setMtu(String(p.interface.mtu));
        setKeepalive(String(p.peer.persistent_keepalive ?? 0));
        setError(null);
      } else submit(p.revision);
    } catch (e) {
      setError(e);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={m.edit.title(profile.name)}
      description={m.edit.description}
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
          <Button
            type="submit"
            form={formId}
            variant="primary"
            pending={update.isPending}
            pendingLabel={ui.common.saving}
          >
            {ui.common.save}
          </Button>
        </>
      }
    >
      <form
        id={formId}
        noValidate
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <FormFailure error={error} onReload={() => void latest(true)} onOverwrite={() => void latest(false)} />
        <Field label={ui.common.name} required error={show(errors.name)}>
          {({ id, describedBy, invalid }) => (
            <Input
              id={id}
              maxLength={64}
              aria-describedby={describedBy}
              aria-invalid={invalid}
              value={name}
              onChange={(e) => {
                setName(e.target.value);
              }}
            />
          )}
        </Field>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Field label={m.edit.country}>
            {({ id }) => (
              <Input
                id={id}
                value={country}
                onChange={(e) => {
                  setCountry(e.target.value);
                }}
              />
            )}
          </Field>
          <Field label={m.edit.city}>
            {({ id }) => (
              <Input
                id={id}
                value={city}
                onChange={(e) => {
                  setCity(e.target.value);
                }}
              />
            )}
          </Field>
          <Field label={m.server}>
            {({ id }) => (
              <Input
                id={id}
                mono
                value={server}
                onChange={(e) => {
                  setServer(e.target.value);
                }}
              />
            )}
          </Field>
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="MTU" hint={m.edit.mtuHint} error={show(errors.mtu)}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                mono
                inputMode="numeric"
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={mtu}
                onChange={(e) => {
                  setMtu(e.target.value);
                }}
              />
            )}
          </Field>
          <Field label={m.edit.keepalive} hint={m.edit.keepaliveHint} error={show(errors.keepalive)}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                mono
                inputMode="numeric"
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={keepalive}
                onChange={(e) => {
                  setKeepalive(e.target.value);
                }}
              />
            )}
          </Field>
        </div>
      </form>
    </Dialog>
  );
}
