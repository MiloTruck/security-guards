# security-guards

Library of guards for Safe accounts.

## Contracts

```ml
guards
├─ Guard - "Base guard meant to be inherited by custom guards"
├─ RestrictiveGuard - "Imposes security restrictions on transactions"
MultiGuard - "Forwards pre and post transaction hooks to multiple guards"
```

## Safety

This is codebase has **not** been audited.

We **do not give any warranties** and **will not be liable for any loss** incurred through any use of this codebase.

## Installation

To install with [**Foundry**](https://github.com/gakonst/foundry):

```sh
forge install MiloTruck/safe-guards
```