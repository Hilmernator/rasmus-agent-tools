# rasmus-plugins

Delbara skills för Codex och Claude Code. Repot innehåller endast **code-validation**.

## Code Validation

[Skill-instruktioner](skills/code-validation/SKILL.md) för granskning av ocommittade kodändringar före commit.

- Granskar staged, unstaged och relevanta nya filer.
- Prioriterar stoppfel, oväntat beteende, kodkvalitet och prestanda.
- Ger fynd med fil/rad, konsekvens och rättningsförslag i ord.
- Ändrar inte kod och gör ingen commit.

## Användning

- Codex: `$code-validation`
- Claude Code: `/code-validation`

Lokalt finns repot i `~/rasmus-plugins`. Mapparna `~/.codex/skills/code-validation` och `~/.claude/skills/code-validation` länkar till `skills/code-validation` här. Redigera den gemensamma källan i repot.

På en annan dator: klona repot och länka eller kopiera `skills/code-validation` till respektive verktygs personliga skillmapp. Kontrollera befintliga installationer innan de ersätts.

Övriga personliga skills underhålls lokalt utanför detta repo.
