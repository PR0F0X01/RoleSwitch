# RoleSwitch

**RoleSwitch** is a **Burp Suite extension** designed to simplify testing the same HTTP request across multiple roles, accounts, and sessions instead of repeatedly copying requests, replacing headers or parameters, switching accounts, and comparing responses manually.

### What makes RoleSwitch different?

**automatic value capture from traffic** with a button. Dynamic values such as CSRF tokens, session-related values, dynamic headers, and parameters can be extracted from traffic instead of being manually searched for and copied.

Another key feature is applying a Header or Parameter configuration to multiple Roles at once while keeping each Role's actual value independent. This significantly simplifies testing when working with many accounts.

The main focus is not simply modifying headers or parameters. Its core purpose is to 

**make multi-role testing extremely easy by running the same request across multiple Roles with minimal interaction**.

You can configure Roles such as `Admin`, `Manager`, `User`, and `Guest`, with each Role maintaining its own Headers, Parameters, Container, Endpoint, extracted dynamic values, and result color. The same request can then be executed across the configured Roles and the results are grouped for comparison.
 
### Quick Tab & Button Reference

**Config Tab**

* **Role Selector** — Select the Role you want to configure.
* **+ Add New Role** — Create a new Role.
* **Color** — Assign a color to identify the Role's results.
* **Container** — Associate the Role with a [Firefox Container](https://addons.mozilla.org/en-US/firefox/addon/pr0f0x01_containerdock/).
* **Header / Parameter Table** — Manage the Role's Headers and Parameters.
* **🎯 Grab Value From Traffic** — Capture a Header or Parameter value directly from traffic and create a reusable fingerprint.
* **Update From Container** — Refresh the Role's values from traffic captured for its Container.
* **Update ALL Roles From Containers** — Refresh all configured Roles from their associated Containers.
* **⚡ Apply Item To ALL Roles** — Apply the same Header/Parameter item to multiple Roles without copying account-specific values.
* **⚡ Apply Endpoint To ALL Roles** — Apply the current Endpoint to all Roles.
* **Delete Role** — Delete the selected Role.
* **🗑 Delete Header/Param From ALL Roles** — Remove a Header/Parameter from multiple Roles at once.
* **Req/sec** — Control request pacing.
* **Save Rate** — Save the configured request rate.
* **Threads** — Configure the worker/thread setting used by the execution workflow.
* **Export JSON...** — Export the Role configuration as JSON.
* **Import JSON...** — Import a previously exported configuration.
  **Results Tab**
* **Results Table** — View executions performed through the configured Roles.
* **Groups** — Keep results from each test operation together.
* **Request** — View the exact request sent for the selected result.
* **Response** — View the server response.
* **Search** — Search within Roles, Requests, or Responses.
* **Columns / Filtering** — Control visible columns such as Status, Size, Time, Host, Method, URL, Params, and Match.

**History Tab**

* **History Table** — View previously handled requests.
* **Resend Selected (All Roles)** — Resend selected requests through all configured Roles.
* **Delete Selected** — Delete selected History entries.
* **Clear History** — Clear the entire History list.

**Burp Context Menu**

* **Send ALL Roles only** — Execute the selected request using all configured Roles.
* **Send ALL Roles With Method** — Generate request variants using methods such as `GET`, `POST`, `PUT`, `PATCH`, and `DELETE`.
* **Apply Role Configuration** — Select a configured Role and apply its predefined Headers and Parameters directly to the current Repeater request, allowing the request to be sent using that Role's identity without running it through all Roles.


### Firefox Companion — [ContainerDock](https://addons.mozilla.org/en-US/firefox/addon/pr0f0x01_containerdock/)

The companion Firefox extension focuses on Container management and fast multi-context browsing. It can open the same target across multiple Firefox Containers and connect each Container identity to the corresponding RoleSwitch Role. It also injects a Container identifier into traffic so Burp can associate captured traffic with the correct Role.

**In short:**
RoleSwitch turns authorization, RBAC, and multi-account testing into a simple workflow: **Roles → Containers/Sessions → automatic value capture → one request → execution across multiple Roles → grouped results and direct comparison**.
؟

---

# Detailed Documentation

This section provides a **complete and detailed explanation of RoleSwitch**, covering all major features, tabs, buttons, controls, workflows, and integrations available in the extension.

Unlike the quick reference above, this section explains **how each feature works, what it does, and how it is used**, including Role configuration, Headers and Parameters, automatic value extraction, Container integration, multi-Role execution, Repeater integration, Results, History, and the Firefox companion extension.

---

# Main Features


## 1. Role Configuration

The **Config** tab is the main workspace.

At the top you have a Role selector that lets you switch between configured roles.

### `+ Add New Role`

Creates a new role.

A role contains:

- Role name
- Color
- Firefox Container name
- Headers / Parameters
- Endpoint

The role name is only an identifier. You can name it whatever matches your testing workflow.

Example:

```text
Admin
Manager
Employee
Viewer
Guest
```

---

## 2. Role Color

Each role can have its own color.

The color is used to make results easier to distinguish when several roles are executed against the same request.

Click the color button next to the Role name to choose a color.

---

## 3. Container

Each role can be associated with a Firefox Container.

Example:

```text
Role: Admin
Container: admin

Role: User
Container: user

Role: Guest
Container: guest
```

The Container name is important when using the companion Firefox extension.

RoleSwitch uses the container identifier injected into requests to associate captured Burp traffic with the correct role/container.

The matching is normalized and uses the exact container name rather than a loose prefix match.

---

# Header / Parameter Table

Every role has an items table:

```text
Type       Key                 Value
---------------------------------------------
Header     Authorization       ...
Header     X-CSRF-Token        ...
Parameter  userId              ...
Parameter  role                ...
```

The supported item types are:

- `Header`
- `Parameter`

The **Value is role-specific**.

This means:

```text
Admin → Authorization = admin-token
User  → Authorization = user-token
Guest → Authorization = guest-token
```

The same Key can exist in multiple roles without forcing the values to be identical.

---

# `Grab Value From Traffic`

This is one of the important features of RoleSwitch.

It is useful for dynamic values such as:

- CSRF tokens
- Session-related values
- Dynamic headers
- Dynamic parameters
- Other values that change between sessions

### How it works

1. Select a Header/Parameter row.
2. Click **Grab Value From Traffic**.
3. Paste the relevant raw traffic.
4. Highlight the value you want to capture.
5. Choose the context length.
6. RoleSwitch builds a fingerprint regex around the selected value.
7. The generated regex is tested against the supplied traffic.
8. Save the value.

The saved fingerprint can later be reused when RoleSwitch updates the role from its container traffic.

A `🎯` marker identifies a Key that has a saved Grab-Value fingerprint.

### Important behavior

The fingerprint is scoped to:

```text
Container + Type + Key
```

So a regex learned for:

```text
Admin container + Header + X-CSRF-Token
```

is not automatically reused for:

```text
User container + Header + X-CSRF-Token
```

unless you explicitly apply it to another role.

This prevents different containers from accidentally sharing extraction logic.

---

# `Update From Container`

This button updates a role from traffic captured for its configured Firefox Container.

Example:

```text
Firefox Container: Admin
        ↓
Browse normally
        ↓
Burp sees the request
        ↓
RoleSwitch associates it with Admin
        ↓
Update From Container
        ↓
Admin role values are refreshed
```

RoleSwitch maintains recent request/response history per container.

It does not rely only on the newest request.

This matters because the newest request might not contain the value you need.

For example:

```text
Request #1 → Authorization
Request #2 → Cookie
Request #3 → X-CSRF-Token
Request #4 → unrelated GET
```

The extension can search the captured history for the relevant Header/Parameter.

The container history is capped at the most recent **100 captured entries per container**.

---

# Endpoint

Each role has an Endpoint field.

You can leave it blank:

```text
Endpoint:
```

When blank, RoleSwitch searches the captured traffic for the configured container.

You can also specify an endpoint such as:

```text
POST /api/account
```

The endpoint matching uses the HTTP method and request path.

The query string is ignored for the path comparison.

This helps avoid accidentally matching a different endpoint with a similar name.

---

# `⚡ Apply Item To ALL Roles`

This is designed for quickly configuring many roles.

Suppose you have 20 roles and want all of them to contain:

```text
Header: X-Test-Context
```

Instead of manually creating the item 20 times:

1. Select the Header/Parameter row.
2. Click **⚡ Apply Item To ALL Roles**.
3. Select the roles.
4. Click **Apply**.

### Important

The **Value is NOT copied**.

Only the configured item information is propagated.

This is intentional because each Role represents a different account/session.

Example:

```text
All roles:
    Header → Authorization

But:

Admin → admin token
User  → user token
Guest → guest token
```

If a saved Grab-Value fingerprint exists for the source role/container, it can also be included when explicitly applying the item.

---

# `⚡ Apply Endpoint To ALL Roles`

Copies the current role's Endpoint to the other roles after confirmation.

Useful when every role should learn/update from the same endpoint.

Example:

```text
POST /api/profile
```

can be applied to all configured roles instead of entering it manually for each one.

---

# Adding / Removing Items

The items table is used to manage the Headers and Parameters belonging to a Role.

Typical workflow:

```text
Add Header
    ↓
Set Key
    ↓
Set Value
    ↓
Optionally teach a Grab-Value fingerprint
```

The extension can replace configured Headers and Parameters in the outgoing request.

For parameters, the extension handles values in supported URL/body formats rather than simply appending another parameter.

---

# `Delete Role`

Deletes the selected role.

There is also a global role-management option:

### `🗑 Delete Role...`

This opens the role deletion workflow from the Config tab.

---

# `🗑 Delete Header/Param From ALL Roles...`

Useful when an item has been added to many roles and you want to remove it globally instead of editing every role individually.

---

# Results

The **Results** tab is where requests executed through the roles are collected.

Each execution can show information such as:

```text
ID
Role
Status
Size
Time
Host
Method
URL
Params
Match
```

The default visible columns are:

```text
ID
Role
Status
Size
```

Additional columns can be enabled through the Results filtering controls.

---

## Groups

Every role execution batch is organized into a **Group**.

For example:

```text
Group 1

Admin     → 200
Manager   → 200
User      → 403
Guest     → 401
```

This keeps the results from one test operation together.

You can perform another test and get another group without losing the previous results.

---

# Request / Response Viewer

Selecting a result displays its request and response using Burp's message editors.

The Results area provides:

```text
Request
Response
```

side by side.

This makes it possible to inspect exactly what was sent for each role and what the server returned.

---

# Result Search

The Results tab includes a search field.

The search can be used to locate information inside:

- Role
- Request
- Response

The search scope can distinguish between:

```text
Request
Response
Both
```

The search remains active until you clear it.

Opening a new Group does not automatically clear the search.

---

# Result Columns / Filtering

The Results interface allows you to control which result columns are visible.

Available columns include:

```text
ID
Role
Status
Size
Time
Host
Method
URL
Params
Match
```

This is useful when you want a compact view for quick authorization testing or a more detailed view during analysis.

---

# History

The **History** tab keeps previously handled requests.

The history table includes:

```text
ID
Method
Path
Size
Time
```

Selecting an entry displays the request in the Burp message editor.

---

## `Resend Selected (All Roles)`

Select one or more History entries and resend them through all configured roles.

This is useful when you want to repeat a previous test without going back to Proxy and finding the original request again.

Example:

```text
History
   ↓
Select request
   ↓
Resend Selected (All Roles)
   ↓
Role A
Role B
Role C
Role D
```

---

## `Delete Selected`

Deletes the selected History entries.

## `Clear History`

Clears the stored History list.

---

# Context Menu Integration

RoleSwitch also integrates with Burp's context menu.

When working with a request inside Burp, the extension can provide actions such as:

### `Send ALL Roles With Method`

The selected request is executed using all configured roles.

### Role + Method Variants

The extension can also generate method variants for the request, including:

```text
GET
POST
PUT
PATCH
DELETE
```

while keeping the relevant request structure for comparison.

This is useful when testing whether endpoint behavior changes when the HTTP method changes.

---

# Request Rate

RoleSwitch provides a **Req/sec** setting.

Example:

```text
Req/sec: 1
```

The setting controls the pacing between generated requests.

Use a conservative rate appropriate for the authorized testing environment.

### `Save Rate`

Stores the configured request rate so it persists across restarts.

---

# Threads

The Config interface also exposes a **Threads** setting.

It controls the configured worker/thread setting used by the request execution workflow.

The extension also has a job queue that prevents multiple submitted RoleSwitch jobs from racing with each other.

---

# Export / Import

RoleSwitch can export the configured role setup to JSON.

### `Export JSON...`

Exports:

- Roles
- Role colors
- Container names
- Endpoints
- Headers
- Parameters
- Relevant saved Grab-Value fingerprints

This makes a RoleSwitch configuration portable.

### `Import JSON...`

Imports a previously exported configuration.

This is useful when you have a standard role setup that you want to reuse across projects or targets.

---

# Persistence

RoleSwitch persists several types of local state, including:

- Results
- History
- Settings
- Grab-Value fingerprints

This means you can close and reopen Burp without necessarily losing the previously stored extension state.

---

# Firefox Companion Extension

RoleSwitch is designed to work with a companion Firefox extension.

## What the Firefox extension does

The Firefox side focuses on **Container management and fast multi-context browsing**.

It can be used to:

- Open the same URL in multiple Firefox Containers.
- Open a predefined group of Containers with one action.
- Avoid manually opening the same target in each Container one by one.
- Inject a Container-identifying HTTP header into traffic.
- Connect browser Container identity to the corresponding RoleSwitch role.

Conceptually:

```text
Firefox
│
├── Admin Container
│      └── Container header → Admin
│
├── User Container
│      └── Container header → User
│
└── Guest Container
       └── Container header → Guest
```

Burp then receives those requests and RoleSwitch can associate the traffic with the correct Container.

---

# Firefox → Burp Integration

The companion extension injects a dedicated Container header.

The Burp extension listens for that identifier in Proxy traffic.

The workflow becomes:

```text
Firefox Container
        │
        │ Container identifier
        ▼
      Burp
        │
        ▼
   RoleSwitch
        │
        ├── Capture request
        ├── Capture response
        ├── Store container history
        └── Update matching Role
```

This is what allows **Update From Container** to work without manually copying tokens from every browser session.

---

# Example Workflow

Imagine you are testing an application with four accounts:

```text
Admin
Manager
Employee
Guest
```

## Step 1 — Create Firefox Containers

Create:

```text
admin
manager
employee
guest
```

## Step 2 — Open the target

Use the Firefox companion extension to open the same target in all four Containers.

## Step 3 — Authenticate

Log into the appropriate account inside each Container.

## Step 4 — Create RoleSwitch roles

Create:

```text
Admin     → admin
Manager   → manager
Employee  → employee
Guest     → guest
```

where the right side is the Firefox Container name.

## Step 5 — Browse normally

Send normal traffic through Burp.

RoleSwitch records the recent traffic associated with each Container.

## Step 6 — Update roles

Use:

```text
Update From Container
```

or:

```text
Update ALL Roles From Containers
```

to refresh configured role values from captured traffic.

## Step 7 — Send a test request

From Burp, use the RoleSwitch context-menu action to execute the request across the configured roles.

## Step 8 — Compare

You can now inspect:

```text
Role
Status
Size
Request
Response
```

for each execution.

---

# The Core Idea

RoleSwitch is built around one simple workflow:

```text
                 ┌───────────────┐
                 │ Original      │
                 │ HTTP Request  │
                 └───────┬───────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
    Role A            Role B            Role C
    Session A         Session B         Session C
        │                │                │
        ▼                ▼                ▼
    Request A         Request B         Request C
        │                │                │
        └────────────────┼────────────────┘
                         ▼
                  Results / Compare
```

The Firefox companion adds the missing browser-side context:

```text
Firefox Containers
        ↓
Container identification
        ↓
Burp
        ↓
RoleSwitch
        ↓
Role-specific request execution
        ↓
Grouped results
```

---

# Intended Use

RoleSwitch is intended for authorized security testing, bug bounty programs, internal assessments, staging environments, and other situations where you have permission to test the target.

It is especially useful for:

- Authorization testing
- Access-control testing
- RBAC testing
- Multi-account testing
- Session testing
- Business-logic testing
- Role-to-role request comparison
- Dynamic token/header handling

Always use it only against systems and accounts you are authorized to test.

---


