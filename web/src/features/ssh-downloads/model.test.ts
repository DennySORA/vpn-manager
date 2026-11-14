import { describe, expect, it } from "vitest";
import { emptyForm, formOf, inputOf } from "./model";
import { job, status } from "./test-fixtures";

describe("the dialog's form follows the server's rules", () => {
  const ok = () => ({
    ...emptyForm([]),
    name: "下載",
    gateway_id: "g1",
    host: "files.example.net",
    user: "puller",
    identity_file: "~/.ssh/id_ed25519",
    source_dir: "/data/todo",
    local_dir: "/home/me/in",
  });

  it("the body keeps stored secrets unless a new one is typed or the stored one cleared", () => {
    const edit = formOf(job());
    let body = inputOf(edit, false);
    expect(body.password).toBeNull();
    expect(body.clear_password).toBe(false);
    expect(body.key_passphrase).toBeNull();
    body = inputOf({ ...edit, password: "new-pass" }, false);
    expect(body.password).toBe("new-pass");
    body = inputOf({ ...edit, clear_password: true }, false);
    expect(body.clear_password).toBe(true);
    // Empty folders go out as null: the server puts them beside the source.
    expect(inputOf({ ...ok(), work_dir: " " }, true).work_dir).toBeNull();
    expect(inputOf({ ...ok(), paused: true }, true).paused).toBe(true);
    expect(inputOf({ ...ok(), paused: true }, false).paused).toBe(false);
    expect(status().state).toBe("idle");
  });
});
