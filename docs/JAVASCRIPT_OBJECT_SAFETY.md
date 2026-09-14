# JavaScript object-safety policy

Household Budget ships one dependency-free production JavaScript file,
`core/static/core/app.js`. Server-rendered templates load that reviewed file and do not contain
inline JavaScript. The client does not parse JSON from users, merge untrusted objects, install a
framework or package, or accept client-side configuration objects.

## Prototype-pollution boundary

Keyed collections that can be selected using runtime data use `Map`, and membership collections use
`Set`. The schedule-field controller therefore resolves the selected recurrence through `Map.get()`
and uses a closed `Set` of fixed element identifiers. An unexpected option, including a magic object
property name, resolves to the empty set and cannot reach an inherited property.

The production client inventory fails closed if a JavaScript file or inline script introduces:

- `__proto__`, `constructor`, or direct `prototype` access;
- `Object.assign`, `Object.defineProperty`, `Object.defineProperties`, `Object.setPrototypeOf`, or
  `Reflect.set`;
- a dynamic bracket-property lookup or assignment; or
- `for ... in` inherited-property iteration.

This deliberately narrow subset prevents untrusted property names from reaching an ordinary object
prototype, avoids recursive or shallow object-merging primitives, and requires an explicit review
before the client can gain a new object-construction path. Fixed DOM properties, fixed `dataset`
properties, arrays iterated by value, and `Map` or `Set` operations remain permitted.

The inventory scans every reviewed production template and static root in both local quality gates
and pull-request CI. It also rejects an unreviewed client root or artifact type, so moving JavaScript
to a new application or extension cannot silently bypass the object-safety rules.

Any future client data parser, third-party script, object merge, dynamic key, state hydration path,
or framework requires a security review and dedicated pollution tests before the allowlist changes.
