# rasmus-plugins

Rasmus egna skills och plugins för Codex och Claude Code.

## Struktur

- `skills/<namn>/SKILL.md`: instruktioner med eventuella referenser och agentmetadata.
- `plugins/`: plats för framtida egna pluginpaket. Inga pluginpaket finns ännu.

## Skills

| Skill | Användning | Beroende |
| --- | --- | --- |
| [code-validation](skills/code-validation/SKILL.md) | Granska ocommittade ändringar utan att ändra kod | Git och repot som ska granskas |
| [youtube-story-script](skills/youtube-story-script/SKILL.md) | Råmaterial till engelskt YouTube-manus | Videobrief och eget råmaterial |
| [youtube-research](skills/youtube-research/SKILL.md) | Belagd YouTube-research och produktionsbrief | Lokala youtube/strategy och dess datainsamlare; annars avgränsad webbresearch |
| [animate](skills/animate/SKILL.md) | Skapa och exportera förklarande animationer | Animation Engine-projektet |
| [architecture-review](skills/architecture-review/SKILL.md) | Granska teknisk korrekthet i animationer | Animation Engine-projektet |

## Lokal användning

Huvudmappen på Rasmus dator är `~/rasmus-plugins`. Redigera personliga skills här.
Installationerna i `~/.codex/skills/<namn>` och `~/.claude/skills/<namn>` är symboliska länkar till respektive mapp här, så båda verktygen läser samma version.

I Codex används exempelvis `$code-validation`; i Claude Code `/code-validation`.
Starta en ny session om en ny skill inte visas. Skill-instruktioner ger inga extra systembehörigheter.

På en annan dator: klona repot och länka önskade skillmappar till verktygets personliga skillmapp. Kontrollera befintliga installationer innan de ersätts. Projektspecifika skills kräver sina projekt och kan innehålla Rasmus lokala sökvägar.

## Ursprung och underhåll

Samlat 2026-10-12 från Rasmus lokala skills och YouTube-projekt. `youtube-story-script` utgår från projektets nyare version med researchkopplingen. Befintliga projektkopior ligger kvar som tidigare; ändringar här synkas inte automatiskt tillbaka till projektens egna skillmappar. Animation Engine har dessutom egna repo-instruktioner och reviewmetoder som fortsatt gäller.

Reverse Engineer Anything, OpenAI:s systemskills och hämtade plugins ingår inte: de underhålls av sina respektive skapare. Säkerhetskopior av tidigare personliga installationer lagras utanför repot.

Claude Codes personliga skillformat: https://code.claude.com/docs/en/skills (kontrollerat 2026-10-12).
