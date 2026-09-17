# UniversalCombatArbiter (PoC)

A **generic** SKSE/CommonLibSSE-NG proof of concept for Skyrim SE/AE combat-arbitration experiments.

## What this is testing

This project deliberately does **not** look for Hoshi-Sanctum Knight, `ShinenHSPlugin.dll`, any Hoshi form, any Hoshi function, or any Hoshi offset.

Instead it defines one attacker-side rule:

> Damage from an actor granted the "absolute damage" property bypasses any *earlier vtable interception* on Skyrim's standard Actor health/death and ActorValueOwner health-write path, by dispatching that one call chain to the pristine Bethesda implementations recovered from the installed Skyrim executable on disk.

The exact same technique applies to **every target**.  If another NPC mod protects actors by replacing the same engine vtable functions, it is covered without adding a compatibility patch for that mod.

That makes the test useful for a "generic technique only" duel rule.  It is not the earlier Hoshi-specific `IsProtectedKnight -> false` idea.

## Mechanism

The plugin recovers pristine function pointers from the user's own on-disk `SkyrimSE.exe`, then installs itself as the outer vtable layer for:

Actor:
- `KillDying` (0xAA)
- `Resurrect` (0xAB)
- `HandleHealthDamage` (0x104)
- `KillImpl` (0x10E)
- `CheckClampDamageModifier` (0x127)

ActorValueOwner:
- `SetBaseActorValue` (0x04)
- `ModBaseActorValue` (0x05)
- `ModActorValue` (0x06)
- `SetActorValue` (0x07)

Normal calls are chained to the previously installed function, preserving other mods.

When an absolute attacker causes `HandleHealthDamage`, a thread-local context is opened for that target.  While the context is active, the above health/death calls dispatch to the pristine Bethesda functions instead of the previously installed chain.  This is a **class-of-technique counter** against vtable-based health/death interception, not a target-specific patch.

Optionally, lethal absolute damage creates a short terminal-death window.  During that window standard `Resurrect` and positive Health writes through these vtable paths are rejected.  Again, this applies identically to every target.

## Why recover pristine functions from disk?

Reading the live vtable is insufficient: another SKSE plugin may already have replaced that slot.  The PE file on disk still contains Bethesda's original vtable entries.  The PoC converts those preferred-image addresses to the current ASLR runtime base.

This also avoids taking a dependency on any opponent DLL's saved-original pointers.

## Configuration

Copy `config/UniversalCombatArbiter.ini` to:

`Data/SKSE/Plugins/UniversalCombatArbiter.ini`

By default `bPlayerHasAbsoluteDamage=1`, so the player is the test attacker.

For a modded challenger NPC, disable the player option and configure its NPC base form by plugin filename and local form ID:

```ini
bPlayerHasAbsoluteDamage=0
sAttackerPlugin=MyChallenger.esp
iAttackerLocalFormID=0x800
```

The target is never configured.

## Expected first test

1. Back up the save and use an isolated profile.
2. Put the DLL in `Data/SKSE/Plugins` and the INI beside it.
3. Leave only the player as the absolute attacker for the first PoC.
4. Hit a protected target with an ordinary weapon.
5. Inspect `Documents/My Games/Skyrim Special Edition/SKSE/UniversalCombatArbiter.log`.
6. Compare actual Health loss before/after the plugin.

The important result is **not whether the target permanently dies yet**.  The first milestone is whether an ordinary hit now reaches normal Health magnitude instead of being reduced/rejected by a vtable protection layer.

## What this PoC does NOT defeat yet

This version is intentionally narrow.  It can still lose to techniques outside the intercepted class, including:

- inline detours placed inside Bethesda's original function bodies;
- direct memory writes to actor state that never use the hooked virtual functions;
- a later plugin that overwrites these vtable slots after this plugin's final re-wrap;
- a custom life-state system that rebuilds the actor without calling standard `Resurrect` or positive Health vfuncs;
- control/AI mechanics such as forced stagger, ragdoll, teleport evasion, animation interruption, or custom movement;
- arbitrary external code that simply disables/deletes/replaces the target.

Those are useful experimental boundaries: if the health bypass works but a target still recovers, the next step is to identify which *generic engine class* that recovery belongs to, rather than add an opponent-name check.

## Engineering risk

This is a proof of concept and has **not been run inside Skyrim in this environment**.  It performs global vtable hooks and should be tested only on an expendable mod profile/save first.

The design avoids temporarily restoring global vtables during an attack.  Instead it keeps its own outer hooks installed and uses a thread-local per-attack context, which reduces the race window substantially.

## Build

Requirements:
- Visual Studio 2022 / clang-cl with C++23
- SKSE64 runtime
- Address Library for SKSE Plugins
- CommonLibSSE-NG installed as a CMake package

Typical configuration:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="C:/path/to/CommonLibSSE-NG/install"
cmake --build build --config Release
```

The output DLL goes in `Data/SKSE/Plugins/`.

## Duel-rule interpretation

Under a rule that permits a competitor to bring its own native DLL but forbids modifying the opponent's files, this design is materially different from a compatibility/destruction patch:

- no opponent module name;
- no opponent form ID;
- no opponent signature/offset;
- no opponent function is patched;
- the same attacker-side mechanic is applied to every actor;
- the counter is defined by an engine-level technique class: *vtable-mediated health/death interception*.

If a totally unrelated enemy implements the same defensive technique, the same build should attempt to bypass it with no changes.
