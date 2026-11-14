import { FilePlus2, Globe, Shield, Sparkles } from "lucide-react";
import { useId, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { apiGet, newIdempotencyKey } from "@/api/client";
import {
  useBlocklists,
  useBuiltinTransports,
  useCapabilities,
  useCreateGateway,
  useCreateInstance,
  useDnsProfiles,
  useGateways,
  useInstances,
  useLifecycle,
  useProfiles,
  useSaveDnsProfile,
  useSaveSecurityProfile,
  useSecurityProfiles,
  useTransportProfiles,
  useUpdateInstance,
} from "@/api/queries";
import type { InstanceInput, InstanceLimits, InstanceSpec, InstanceView, RuntimeProfile } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Disclosure } from "@/components/ui/disclosure";
import { Field, Input, Select } from "@/components/ui/field";
import { FormFailure } from "@/components/ui/form-failure";
import { CARD } from "@/components/ui/look";
import { Menu, MenuItem } from "@/components/ui/menu";
import { m as ui } from "@/components/ui/messages";
import { Callout, EmptyState } from "@/components/ui/states";
import { Switch } from "@/components/ui/switch";
import { reportFailure, toast } from "@/components/ui/toast";
import {
  DNS_PRESETS,
  type DnsPreset,
  findPresetProfile,
  innerPreset,
  presetInput,
  serverHost,
} from "@/features/dns/presets";
import { useSuggestedPort } from "@/features/gateways/ports";
import { allowRangesInput, defaultLists } from "@/features/security/model";
import { AUTO_KEY, brief, choices, mibText, refValue, tcpStartBytes, udpBytes } from "@/features/transport/model";
import { localized } from "@/i18n";
import { isPrivateRange, notCovered, parseCidr } from "@/lib/cidr";
import { cn } from "@/lib/cn";
import { parseIntField, serverFieldErrors, useOpenSession } from "@/lib/forms";
import { useIntentKey } from "@/lib/intent";
import { placeText } from "@/lib/places";
import { capInput, parseCap } from "@/features/limits/model";
import { m } from "./dialogs/messages";
import { m as instanceText } from "./messages";
import { defaultProfile, isRunning, keyUsers, tcpCapacity } from "./model";
import { workerInput } from "./worker-input";

const DEFAULT_LIMITS: InstanceLimits = {
  max_tcp_flows: 1024,
  max_udp_flows: 512,
  memory_mib: 512,
  download_bps: null,
  upload_bps: null,
};

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Edit this Instance; create when absent. */
  instance?: InstanceView;
  /** A new connection starts from this WireGuard profile (e.g. right after importing it). */
  profileId?: string | undefined;
}

export function InstanceDialog(props: Props) {
  const session = useOpenSession(props.open);
  return <InstanceDialogBody key={session} {...props} />;
}

function profileLabel(p: Pick<RuntimeProfile, "name" | "location">) {
  const where = p.location ? placeText({ ...p.location, server: null }) : null;
  return where ? m.profileOption(p.name, where) : p.name;
}

function InstanceDialogBody({ open, onOpenChange, instance, profileId: preset }: Props) {
  const profiles = useProfiles();
  const instances = useInstances();
  const dns = useDnsProfiles();
  const security = useSecurityProfiles();
  const builtinTransports = useBuiltinTransports();
  const savedTransports = useTransportProfiles();
  const blocklists = useBlocklists();
  const gateways = useGateways();
  const create = useCreateInstance();
  const update = useUpdateInstance();
  const createGateway = useCreateGateway();
  const createDns = useSaveDnsProfile();
  const createSecurity = useSaveSecurityProfile();
  const lifecycle = useLifecycle();
  const intent = useIntentKey(`instance.save:${instance?.spec.id ?? "new"}`);
  const dnsIntent = useIntentKey("instance.dns-preset");
  const securityIntent = useIntentKey("instance.allow-ranges");
  const navigate = useNavigate();
  const formId = useId();
  const spec = instance?.spec;
  // A notice that a choice resolves goes away with its button: focus moves to the field now holding
  // the choice, unless the user has already moved on.
  const dnsSelect = useRef<HTMLSelectElement>(null);
  const securitySelect = useRef<HTMLSelectElement>(null);
  const dnsNotice = useRef<HTMLDivElement>(null);
  const securityNotice = useRef<HTMLDivElement>(null);
  const focusAfterMenu = useRef<HTMLElement | null>(null);
  const keepFocus = (notice: HTMLElement | null, target: HTMLElement | null) => {
    const active = document.activeElement;
    if (!active || active === document.body || notice?.contains(active)) target?.focus();
  };

  // A new connection starts from a suggested profile and its name until the user picks or types
  // another (the suggestion follows the data as it loads; a choice is kept).
  const [chosenProfile, setProfileId] = useState<string | null>(spec?.profile_id ?? preset ?? null);
  const listed = (id: string | null) => id !== null && (profiles.data?.some((p) => p.id === id) ?? true);
  const profileId =
    spec || listed(chosenProfile)
      ? (chosenProfile ?? "")
      : (defaultProfile(profiles.data ?? [], instances.data ?? [])?.id ?? "");
  const profile = profiles.data?.find((p) => p.id === profileId);
  const [typedName, setName] = useState<string | null>(spec?.name ?? null);
  const name = typedName ?? profile?.name ?? "";
  const [dnsId, setDnsId] = useState(spec?.dns_profile_id ?? "");
  const [securityId, setSecurityId] = useState(spec?.security_profile_id ?? "");
  // The transport profile, by what names it in the list (a built-in's key, a saved profile's id).
  const [transportValue, setTransportValue] = useState(spec ? refValue(spec.transport) : AUTO_KEY);
  const transports = choices(builtinTransports.data ?? [], savedTransports.data ?? []);
  const transport = transports.find((c) => c.value === transportValue);
  const base = spec?.limits ?? DEFAULT_LIMITS;
  const [tcp, setTcp] = useState(String(base.max_tcp_flows));
  const [udp, setUdp] = useState(String(base.max_udp_flows));
  const [mem, setMem] = useState(String(base.memory_mib));
  const [down, setDown] = useState(capInput(base.download_bps ?? null));
  const [up, setUp] = useState(capInput(base.upload_bps ?? null));
  // Linux strict mode: offered only where the manager proved this host can build the sandbox.
  const capabilities = useCapabilities();
  const strictCapability = capabilities.data?.find((c) => c.name === "strict_netns");
  const strictAvailable = strictCapability?.state === "supported";
  const [strict, setStrict] = useState(spec?.strict ?? false);
  const strictNote = strictAvailable
    ? m.strict.note
    : capabilities.isPending
      ? m.strict.checking
      : capabilities.isError
        ? m.strict.unknown
        : strictCapability?.reason
          ? localized(strictCapability.reason)
          : m.strict.unsupported;
  const [withGateway, setWithGateway] = useState(true);
  const suggestedPort = useSuggestedPort(
    (gateways.data ?? []).map((g) => g.port),
    open && !spec && withGateway,
  );
  const [typedPort, setGwPort] = useState<string | null>(null);
  const gwPort = typedPort ?? String(suggestedPort);
  const [startNow, setStartNow] = useState(true);
  const [revision, setRevision] = useState(spec?.revision);
  // What the worker takes from the version the form was loaded from (the name is not part of it).
  const [loaded, setLoaded] = useState(spec ? { revision: spec.revision, worker: workerInput.instance(spec) } : null);
  const [error, setError] = useState<unknown>(null);
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  // One WireGuard key serves one running connection at a time.
  const sharing = profileId ? keyUsers(profileId, profiles.data ?? [], instances.data ?? [], spec?.id) : [];
  const sharingNames = sharing.map((v) => v.spec.name);
  const keyNote = !sharing.length
    ? null
    : sharing.some(isRunning)
      ? m.key.inUseRunning(sharingNames)
      : m.key.inUse(sharingNames);
  // Without resolvers in the profile, the connection cannot start until it has a DNS profile.
  const needsDns = profile?.interface.dns.length === 0;
  // AllowedIPs only private: the default policy (and a profile not allowing them) refuses all of it.
  const allowed = profile?.peer.allowed_ips ?? [];
  // A resolver outside AllowedIPs is unreachable: the tunnel does not carry its queries.
  const inTunnel = (ip: string) =>
    parseCidr(ip) !== null && !ip.includes("/") && notCovered([ip], allowed).length === 0;
  const presetReachable = (p: DnsPreset) => inTunnel(serverHost(p.server.address));
  const anyPresetReachable = DNS_PRESETS.some(presetReachable);
  // An existing DNS profile whose resolvers this tunnel reaches: offered before creating another.
  const usableDns = dns.data?.find(
    (d) => d.servers.length > 0 && d.servers.every((sv) => inTunnel(serverHost(sv.address))),
  );
  const [innerDns, setInnerDns] = useState("");
  const innerDnsValid = inTunnel(innerDns.trim());
  const innerExample = (() => {
    const v4 = allowed.find((a) => !a.includes(":"));
    const base = v4?.split("/")[0]?.split(".");
    return base?.length === 4 ? `${base.slice(0, 3).join(".")}.1` : "10.0.0.1";
  })();
  const chosenSecurity = security.data?.find((p) => p.id === securityId);
  const refused =
    allowed.length > 0 && allowed.every(isPrivateRange) ? notCovered(allowed, chosenSecurity?.allow_private ?? []) : [];
  const covering = refused.length
    ? security.data?.find((p) => p.id !== securityId && notCovered(allowed, p.allow_private).length === 0)
    : undefined;

  const server = serverFieldErrors(error);
  const tcpN = parseIntField(tcp);
  const udpN = parseIntField(udp);
  const memN = parseIntField(mem);
  const downCap = parseCap(down);
  const upCap = parseCap(up);
  const portN = parseIntField(gwPort);
  const portClash = portN !== null ? gateways.data?.find((g) => g.port === portN) : undefined;
  const errors = {
    name: !name.trim() ? ui.common.enterName : (server.get("/name") ?? null),
    profile: !profileId ? m.errors.profile : (server.get("/profile_id") ?? null),
    dns: needsDns && !dnsId ? m.errors.dns : (server.get("/dns_profile_id") ?? null),
    tcp: tcpN === null || tcpN < 1 || tcpN > 16384 ? "1–16384" : (server.get("/limits/max_tcp_flows") ?? null),
    udp: udpN === null || udpN < 1 || udpN > 16384 ? "1–16384" : (server.get("/limits/max_udp_flows") ?? null),
    mem: memN === null || memN < 64 || memN > 8192 ? "64–8192 MiB" : (server.get("/limits/memory_mib") ?? null),
    down: downCap.error ?? server.get("/limits/download_bps") ?? null,
    up: upCap.error ?? server.get("/limits/upload_bps") ?? null,
    port:
      instance || !withGateway
        ? null
        : portN === null || portN < 1024 || portN > 65535
          ? m.errors.port
          : portClash
            ? m.errors.portTaken(portClash.name)
            : null,
  };
  const valid = Object.values(errors).every((e) => e === null);
  const show = (msg: string | null) => (submitted || error ? msg : null);
  const pending = busy !== null;
  // What a connection reserves as it opens depends on the transport profile chosen above.
  const flowBytes = tcpStartBytes(transport, transports);
  const capacity =
    tcpN !== null && memN !== null && !errors.tcp && !errors.mem
      ? tcpCapacity({ max_tcp_flows: tcpN, memory_mib: memN }, flowBytes)
      : null;

  const limitsChanged =
    tcpN !== base.max_tcp_flows ||
    udpN !== base.max_udp_flows ||
    memN !== base.memory_mib ||
    downCap.bps !== (base.download_bps ?? null) ||
    upCap.bps !== (base.upload_bps ?? null);
  const input = (): InstanceInput => ({
    name: name.trim(),
    profile_id: profileId,
    dns_profile_id: dnsId || null,
    security_profile_id: securityId || null,
    limits:
      spec || limitsChanged
        ? {
            max_tcp_flows: tcpN ?? base.max_tcp_flows,
            max_udp_flows: udpN ?? base.max_udp_flows,
            memory_mib: memN ?? base.memory_mib,
            download_bps: downCap.bps,
            upload_bps: upCap.bps,
          }
        : null,
    strict,
    // Until the profiles are loaded the saved choice stands (a new connection takes the automatic one).
    ...(transport ? { transport: transport.ref } : {}),
  });

  /** A one-server DNS profile from a preset (an identical existing one is reused), selected here. */
  const applyPreset = (p: DnsPreset) => {
    if (createDns.isPending) return;
    const existing = findPresetProfile(dns.data ?? [], p);
    if (existing) {
      setDnsId(existing.id);
      focusAfterMenu.current = dnsSelect.current;
      return;
    }
    const body = presetInput(p);
    createDns.mutate(
      { input: body, key: dnsIntent.next(body) },
      {
        onSuccess: (r) => {
          dnsIntent.settle();
          keepFocus(dnsNotice.current, dnsSelect.current);
          setDnsId(r.data.id);
          toast.success(m.toast.dnsCreated(r.data.name), m.toast.selected);
        },
        onError: (e) => {
          dnsIntent.settle(e);
          reportFailure(m.intent.dns(body.name), e);
        },
      },
    );
  };

  /**
   * A security profile allowing exactly the profile's private AllowedIPs, selected here. It keeps the
   * default policy's protection: the enabled built-in blocklists and auto-ban.
   */
  const allowRanges = () => {
    const body = allowRangesInput(allowed, m.allowRangesName(profile?.name ?? ""), defaultLists(blocklists.data ?? []));
    createSecurity.mutate(
      { input: body, key: securityIntent.next(body) },
      {
        onSuccess: (r) => {
          securityIntent.settle();
          keepFocus(securityNotice.current, securitySelect.current);
          setSecurityId(r.data.id);
          toast.success(m.toast.securityCreated(r.data.name), m.toast.selected);
        },
        onError: (e) => {
          securityIntent.settle(e);
          reportFailure(m.intent.security(body.name), e);
        },
      },
    );
  };

  /** After the Instance exists: the optional Gateway and start, each reported on its own. */
  const followUps = async (created: InstanceSpec) => {
    if (withGateway && portN !== null) {
      setBusy(m.creatingGateway);
      try {
        await createGateway.mutateAsync({
          key: newIdempotencyKey(),
          input: {
            instance_id: created.id,
            name: m.gatewayName(portN),
            kind: "mixed",
            port: portN,
            enabled: true,
            udp: true,
            max_connections: 1024,
          },
        });
      } catch (e) {
        reportFailure(m.intent.gateway, e);
      }
    }
    if (startNow) {
      setBusy(ui.common.starting);
      try {
        await lifecycle.mutateAsync({ key: newIdempotencyKey(), id: created.id, action: "start" });
      } catch (e) {
        reportFailure(instanceText.intent.start(created.name), e);
      }
    }
  };

  /** The new Instance exists: its follow-ups, then the dialog closes on its page. */
  const created = async (s: InstanceSpec) => {
    await followUps(s);
    setBusy(null);
    toast.success(m.toast.created(s.name), withGateway && portN !== null ? m.toast.createdGateway(portN) : undefined);
    onOpenChange(false);
    void navigate(`/instances/${s.id}`);
  };

  const submit = (rev = revision) => {
    setSubmitted(true);
    if (!valid) return;
    const body = input();
    // The port being created stays as sent while the new Gateway changes the suggestion.
    if (!spec && typedPort === null) setGwPort(gwPort);
    setError(null);
    if (spec && rev !== undefined) {
      // A rename alone changes nothing the running worker uses.
      const workerChanged = rev !== loaded?.revision || loaded.worker !== workerInput.instance(body);
      setBusy(ui.common.saving);
      update.mutate(
        { id: spec.id, revision: rev, input: body, key: intent.next({ id: spec.id, rev, body }) },
        {
          onSuccess: () => {
            intent.settle();
            toast.success(
              m.toast.updated(body.name),
              workerChanged && instance.status?.running ? m.toast.updatedRestart : undefined,
            );
            onOpenChange(false);
          },
          onError: (e) => {
            intent.settle(e);
            setError(e);
          },
          onSettled: () => {
            setBusy(null);
          },
        },
      );
      return;
    }
    setBusy(ui.common.creating);
    create.mutate(
      { input: body, key: intent.next(body) },
      {
        onSuccess: (r) => {
          intent.settle();
          void created(r.data.spec);
        },
        onError: (e) => {
          intent.settle(e);
          setError(e);
          setBusy(null);
        },
      },
    );
  };

  const latest = async (apply: boolean) => {
    if (!spec) return;
    try {
      const v = await apiGet<InstanceView>(`/v1/instances/${spec.id}`);
      setRevision(v.spec.revision);
      if (apply) {
        setLoaded({ revision: v.spec.revision, worker: workerInput.instance(v.spec) });
        setName(v.spec.name);
        setProfileId(v.spec.profile_id);
        setDnsId(v.spec.dns_profile_id ?? "");
        setSecurityId(v.spec.security_profile_id ?? "");
        setTransportValue(refValue(v.spec.transport));
        setTcp(String(v.spec.limits.max_tcp_flows));
        setUdp(String(v.spec.limits.max_udp_flows));
        setMem(String(v.spec.limits.memory_mib));
        setDown(capInput(v.spec.limits.download_bps));
        setUp(capInput(v.spec.limits.upload_bps));
        setError(null);
      } else {
        submit(v.spec.revision);
      }
    } catch (e) {
      setError(e);
    }
  };

  const noProfiles = profiles.isSuccess && profiles.data.length === 0;
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      width={600}
      title={spec ? m.title.edit(spec.name) : m.title.create}
      description={spec ? m.description.edit : m.description.create}
      footer={
        noProfiles ? (
          <Button
            variant="ghost"
            onClick={() => {
              onOpenChange(false);
            }}
          >
            {ui.common.close}
          </Button>
        ) : (
          <>
            <Button
              variant="ghost"
              onClick={() => {
                onOpenChange(false);
              }}
            >
              {ui.common.cancel}
            </Button>
            <Button type="submit" form={formId} variant="primary" pending={pending} pendingLabel={busy ?? ui.working}>
              {spec ? ui.common.save : m.submitCreate}
            </Button>
          </>
        )
      }
    >
      {noProfiles ? (
        <EmptyState
          compact
          icon={FilePlus2}
          title={m.noProfiles.title}
          actions={
            <Button
              variant="primary"
              size="sm"
              onClick={() => {
                onOpenChange(false);
                void navigate("/profiles?import=1");
              }}
            >
              {m.noProfiles.import}
            </Button>
          }
        >
          {m.noProfiles.body}
        </EmptyState>
      ) : (
        <form
          id={formId}
          noValidate
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
          className="space-y-5"
        >
          <FormFailure error={error} onReload={() => void latest(true)} onOverwrite={() => void latest(false)} />
          <Field label={ui.common.name} required error={show(errors.name)}>
            {({ id, describedBy, invalid }) => (
              <Input
                id={id}
                // eslint-disable-next-line jsx-a11y/no-autofocus -- the dialog's first field: the dialog opens to type its name
                autoFocus
                maxLength={64}
                placeholder={m.fields.namePlaceholder}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                }}
              />
            )}
          </Field>
          <Field
            label={m.fields.profile}
            required
            hint={m.fields.profileHint}
            warning={keyNote}
            error={show(errors.profile)}
          >
            {({ id, describedBy, invalid }) => (
              <Select
                id={id}
                aria-describedby={describedBy}
                aria-invalid={invalid}
                value={profileId}
                onChange={(e) => {
                  setProfileId(e.target.value);
                }}
              >
                {!profileId ? <option value="">{m.fields.chooseProfile}</option> : null}
                {(profiles.data ?? []).map((p) => (
                  <option key={p.id} value={p.id}>
                    {profileLabel(p)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field
              label="DNS"
              required={needsDns}
              hint={needsDns ? undefined : m.fields.dnsHint}
              error={show(errors.dns)}
            >
              {({ id, describedBy, invalid }) => (
                <Select
                  ref={dnsSelect}
                  id={id}
                  aria-describedby={describedBy}
                  aria-invalid={invalid}
                  value={dnsId}
                  onChange={(e) => {
                    setDnsId(e.target.value);
                  }}
                >
                  <option value="">{needsDns ? m.fields.chooseDns : m.fields.profileDns}</option>
                  {(dns.data ?? []).map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label={m.fields.security} hint={m.fields.securityHint}>
              {({ id, describedBy }) => (
                <Select
                  ref={securitySelect}
                  id={id}
                  aria-describedby={describedBy}
                  value={securityId}
                  onChange={(e) => {
                    setSecurityId(e.target.value);
                  }}
                >
                  <option value="">{m.fields.defaultSecurity}</option>
                  {(security.data ?? []).map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          </div>
          <Field
            label={m.fields.transport}
            hint={
              transport
                ? m.fields.transportHint(transport.summary ?? brief(transport, transports))
                : m.fields.transportNone
            }
          >
            {({ id, describedBy }) => (
              <Select
                id={id}
                aria-describedby={describedBy}
                value={transport ? transportValue : ""}
                onChange={(e) => {
                  setTransportValue(e.target.value);
                }}
              >
                {!transport ? (
                  <option value="">{spec ? m.fields.transportCurrent : m.fields.transportAuto}</option>
                ) : null}
                <optgroup label={ui.common.builtIn}>
                  {transports
                    .filter((c) => c.builtin)
                    .map((c) => (
                      <option key={c.value} value={c.value}>
                        {c.name}
                      </option>
                    ))}
                </optgroup>
                {transports.some((c) => !c.builtin) ? (
                  <optgroup label={m.fields.mine}>
                    {transports
                      .filter((c) => !c.builtin)
                      .map((c) => (
                        <option key={c.value} value={c.value}>
                          {c.name}
                        </option>
                      ))}
                  </optgroup>
                ) : null}
              </Select>
            )}
          </Field>
          {needsDns && !dnsId ? (
            <div ref={dnsNotice}>
              <Callout
                tone="warning"
                title={m.dnsNotice.title}
                actions={
                  <>
                    {usableDns ? (
                      <Button
                        size="sm"
                        icon={Globe}
                        onClick={() => {
                          dnsSelect.current?.focus();
                          setDnsId(usableDns.id);
                        }}
                      >
                        {m.useInstead(usableDns.name)}
                      </Button>
                    ) : null}
                    {/* When no preset is reachable through this tunnel there is nothing to offer here. */}
                    {anyPresetReachable ? (
                      <Menu
                        align="start"
                        onCloseAutoFocus={(e) => {
                          const target = focusAfterMenu.current;
                          focusAfterMenu.current = null;
                          if (target) {
                            e.preventDefault();
                            target.focus();
                          }
                        }}
                        trigger={
                          <Button
                            size="sm"
                            icon={Sparkles}
                            pending={createDns.isPending}
                            pendingLabel={ui.common.creating}
                          >
                            {m.dnsNotice.preset}
                          </Button>
                        }
                      >
                        {DNS_PRESETS.map((p) => (
                          <MenuItem
                            key={p.label}
                            icon={Globe}
                            onSelect={() => {
                              applyPreset(p);
                            }}
                            disabled={!presetReachable(p)}
                            reason={presetReachable(p) ? undefined : m.dnsNotice.unreachable}
                          >
                            {p.label}
                          </MenuItem>
                        ))}
                      </Menu>
                    ) : null}
                  </>
                }
              >
                {anyPresetReachable
                  ? m.dnsNotice.needsPreset(Boolean(dns.data?.length))
                  : m.dnsNotice.needsInner(allowed, Boolean(usableDns))}
                {!DNS_PRESETS.every(presetReachable) ? (
                  <span className="mt-2.5 flex items-center gap-2">
                    <Input
                      mono
                      name="inner-dns"
                      aria-label={m.dnsNotice.innerLabel}
                      placeholder={m.dnsNotice.innerPlaceholder(innerExample)}
                      value={innerDns}
                      onChange={(e) => {
                        setInnerDns(e.target.value);
                      }}
                      className="max-w-48"
                    />
                    <Button
                      size="sm"
                      disabled={!innerDnsValid}
                      pending={createDns.isPending}
                      pendingLabel={ui.common.creating}
                      onClick={() => {
                        applyPreset(innerPreset(innerDns.trim()));
                      }}
                    >
                      {m.dnsNotice.useInner}
                    </Button>
                    {innerDns.trim() && !innerDnsValid ? (
                      <span className="text-caption text-danger">{m.dnsNotice.innerInvalid}</span>
                    ) : null}
                  </span>
                ) : null}
              </Callout>
            </div>
          ) : null}
          {refused.length ? (
            <div ref={securityNotice}>
              <Callout
                tone="warning"
                title={m.privateNotice.title}
                actions={
                  covering ? (
                    <Button
                      size="sm"
                      icon={Shield}
                      onClick={() => {
                        securitySelect.current?.focus();
                        setSecurityId(covering.id);
                      }}
                    >
                      {m.useInstead(covering.name)}
                    </Button>
                  ) : !chosenSecurity ? (
                    <Button
                      size="sm"
                      icon={Shield}
                      pending={createSecurity.isPending}
                      pendingLabel={ui.common.creating}
                      onClick={allowRanges}
                    >
                      {m.privateNotice.create}
                    </Button>
                  ) : null
                }
              >
                {m.privateNotice.body(
                  (text) => (
                    <span className="font-mono">{text}</span>
                  ),
                  allowed,
                  chosenSecurity ? chosenSecurity.name : null,
                  refused,
                )}
              </Callout>
            </div>
          ) : null}

          {!spec ? (
            <div className={cn(CARD, "space-y-3 px-3.5 py-3")}>
              <Switch
                checked={withGateway}
                onCheckedChange={setWithGateway}
                label={m.extras.withGateway}
                description={m.extras.withGatewayNote}
              />
              {withGateway ? (
                <Field label={m.extras.port} error={show(errors.port)} className="pl-12">
                  {({ id, describedBy, invalid }) => (
                    <Input
                      id={id}
                      mono
                      inputMode="numeric"
                      autoComplete="off"
                      className="w-32"
                      aria-describedby={describedBy}
                      aria-invalid={invalid}
                      value={gwPort}
                      onChange={(e) => {
                        setGwPort(e.target.value);
                      }}
                    />
                  )}
                </Field>
              ) : null}
              <Switch
                checked={startNow}
                onCheckedChange={setStartNow}
                label={m.extras.startNow}
                description={m.extras.startNowNote}
              />
            </div>
          ) : null}

          <div className={cn(CARD, "px-3.5 py-3")}>
            <Switch
              checked={strict}
              onCheckedChange={setStrict}
              // Turning it off always works; on only where the host supports it.
              disabled={!strict && !strictAvailable}
              label={m.strict.label}
              description={strictNote}
            />
          </div>

          <Disclosure
            className={cn(CARD, "px-3.5 py-2")}
            summary={<span className="font-medium">{m.limits.title}</span>}
            defaultOpen={
              ([errors.tcp, errors.udp, errors.mem, errors.down, errors.up].some(Boolean) && submitted) ||
              Boolean(spec?.limits.download_bps ?? spec?.limits.upload_bps)
            }
          >
            <div className="mt-1 grid gap-3 sm:grid-cols-3">
              <Field label={m.limits.tcp} error={show(errors.tcp)}>
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    mono
                    inputMode="numeric"
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    value={tcp}
                    onChange={(e) => {
                      setTcp(e.target.value);
                    }}
                  />
                )}
              </Field>
              <Field label={m.limits.udp} error={show(errors.udp)}>
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    mono
                    inputMode="numeric"
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    value={udp}
                    onChange={(e) => {
                      setUdp(e.target.value);
                    }}
                  />
                )}
              </Field>
              <Field label={m.limits.memory} error={show(errors.mem)}>
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    mono
                    inputMode="numeric"
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    value={mem}
                    onChange={(e) => {
                      setMem(e.target.value);
                    }}
                  />
                )}
              </Field>
            </div>
            <div className="mt-2.5 space-y-1 text-caption text-fg-tertiary">
              {capacity ? (
                <p>
                  {m.limits.capacity(
                    (value) => (
                      <span className="font-mono tabular-nums text-fg-secondary">{value}</span>
                    ),
                    capacity.limit,
                    capacity.byMemory,
                    capacity.reservedFlows,
                    capacity.reservedMib,
                  )}
                </p>
              ) : null}
              <p>{m.limits.budget(mibText(flowBytes), mibText(udpBytes(transport, transports)))}</p>
            </div>
            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              <Field label={m.limits.download} error={show(errors.down)}>
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    mono
                    inputMode="decimal"
                    placeholder={ui.common.unlimited}
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    value={down}
                    onChange={(e) => {
                      setDown(e.target.value);
                    }}
                  />
                )}
              </Field>
              <Field label={m.limits.upload} error={show(errors.up)}>
                {({ id, describedBy, invalid }) => (
                  <Input
                    id={id}
                    mono
                    inputMode="decimal"
                    placeholder={ui.common.unlimited}
                    aria-describedby={describedBy}
                    aria-invalid={invalid}
                    value={up}
                    onChange={(e) => {
                      setUp(e.target.value);
                    }}
                  />
                )}
              </Field>
            </div>
            <p className="mt-2.5 text-caption text-fg-tertiary">{m.limits.bandwidth}</p>
          </Disclosure>
        </form>
      )}
    </Dialog>
  );
}
