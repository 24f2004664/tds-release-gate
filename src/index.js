const REQUIRED_PERMISSIONS = {
  contents: "read",
  packages: "write",
  "id-token": "none"
};

const VIOLATIONS = {
  EXCESS_PERMISSION: "EXCESS_PERMISSION",
  UNSAFE_PR_TRIGGER: "UNSAFE_PR_TRIGGER",
  TESTS_INCOMPLETE: "TESTS_INCOMPLETE",
  MUTABLE_ACTION: "MUTABLE_ACTION",
  SINGLE_STAGE_IMAGE: "SINGLE_STAGE_IMAGE",
  ROOT_RUNTIME: "ROOT_RUNTIME",
  SECRET_IN_LAYER: "SECRET_IN_LAYER",
  CRITICAL_CVE: "CRITICAL_CVE",
  UNPINNED_IMAGE: "UNPINNED_IMAGE",
  INVALID_PRODUCTION_REF: "INVALID_PRODUCTION_REF",
  APPROVAL_REQUIRED: "APPROVAL_REQUIRED"
};

function reply(decision, violations) {
  return Response.json({
    decision,
    violations
  });
}

function isObject(value) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value);
}

function isFullSha(value) {
  return typeof value === "string" &&
    /^[0-9a-f]{40}$/.test(value);
}

export default {
  async fetch(request) {

    const url = new URL(request.url);

    // Only POST /release-gate
    if (
      request.method !== "POST" ||
      url.pathname !== "/release-gate"
    ) {
      return reply("block", ["UNSAFE_PR_TRIGGER"]);
    }

    let body;

    try {
      body = await request.json();
    } catch {
      return reply("block", ["TESTS_INCOMPLETE"]);
    }

    const violations = [];

    const workflow = isObject(body.workflow)
      ? body.workflow
      : {};

    const permissions = isObject(workflow.permissions)
      ? workflow.permissions
      : {};

    const image = isObject(body.image)
      ? body.image
      : {};

    // ------------------------------------------------
    // 1. Permissions must be EXACTLY:
    //
    // contents: read
    // packages: write
    // id-token: none
    // ------------------------------------------------

    const permissionKeys = Object.keys(permissions);

    if (
      permissionKeys.length !== 3 ||
      permissions.contents !== REQUIRED_PERMISSIONS.contents ||
      permissions.packages !== REQUIRED_PERMISSIONS.packages ||
      permissions["id-token"] !== REQUIRED_PERMISSIONS["id-token"]
    ) {
      violations.push(VIOLATIONS.EXCESS_PERMISSION);
    }


    // ------------------------------------------------
    // 2. Pull requests must use pull_request
    // Never pull_request_target
    // ------------------------------------------------

    if (
      body.event === "pull_request" &&
      workflow.trigger !== "pull_request"
    ) {
      violations.push(VIOLATIONS.UNSAFE_PR_TRIGGER);
    }


    if (
      workflow.trigger === "pull_request_target"
    ) {
      violations.push(VIOLATIONS.UNSAFE_PR_TRIGGER);
    }


    // ------------------------------------------------
    // 3. Tests / matrix
    //
    // testsPassed must be true
    // matrixComplete must be true
    // failFast must be false
    // ------------------------------------------------

    if (
      workflow.testsPassed !== true ||
      workflow.matrixComplete !== true ||
      workflow.failFast !== false
    ) {
      violations.push(VIOLATIONS.TESTS_INCOMPLETE);
    }


    // ------------------------------------------------
    // 4. Action pinning
    //
    // actions/* may use version tags.
    // Third-party actions MUST use full 40-char SHA.
    // ------------------------------------------------

    if (Array.isArray(workflow.actions)) {

      for (const action of workflow.actions) {

        if (!isObject(action)) {
          violations.push(VIOLATIONS.MUTABLE_ACTION);
          continue;
        }

        const owner = action.owner;
        const ref = action.ref;

        if (owner === "actions") {
          // actions-owned actions may use a version tag.
          continue;
        }

        if (!isFullSha(ref)) {
          violations.push(VIOLATIONS.MUTABLE_ACTION);
        }
      }
    }


    // ------------------------------------------------
    // 5. Image must be multi-stage
    // ------------------------------------------------

    if (image.multiStage !== true) {
      violations.push(VIOLATIONS.SINGLE_STAGE_IMAGE);
    }


    // ------------------------------------------------
    // 6. Image must not run as root
    // ------------------------------------------------

    if (image.runsAsRoot !== false) {
      violations.push(VIOLATIONS.ROOT_RUNTIME);
    }


    // ------------------------------------------------
    // 7. Secrets
    //
    // none and buildkit are safe.
    // arg and copy are unsafe.
    // ------------------------------------------------

    if (
      image.secretMode === "arg" ||
      image.secretMode === "copy"
    ) {
      violations.push(VIOLATIONS.SECRET_IN_LAYER);
    }


    // ------------------------------------------------
    // 8. No critical vulnerabilities
    // ------------------------------------------------

    if (
      typeof image.criticalVulnerabilities !== "number" ||
      image.criticalVulnerabilities !== 0
    ) {
      violations.push(VIOLATIONS.CRITICAL_CVE);
    }


    // ------------------------------------------------
    // 9. Image must be digest pinned
    // ------------------------------------------------

    if (image.digestPinned !== true) {
      violations.push(VIOLATIONS.UNPINNED_IMAGE);
    }


    // ------------------------------------------------
    // 10. Production must be pushed to main
    // ------------------------------------------------

    if (
      body.target === "production" &&
      (
        body.event !== "push" ||
        body.ref !== "refs/heads/main"
      )
    ) {
      violations.push(VIOLATIONS.INVALID_PRODUCTION_REF);
    }


    // ------------------------------------------------
    // 11. Production requires approval
    // ------------------------------------------------

    if (
      body.target === "production" &&
      workflow.environmentApproval !== true
    ) {
      violations.push(VIOLATIONS.APPROVAL_REQUIRED);
    }


    // ------------------------------------------------
    // Final decision
    // ------------------------------------------------

    if (violations.length === 0) {
      return reply("promote", []);
    }

    return reply("block", violations);
  }
};