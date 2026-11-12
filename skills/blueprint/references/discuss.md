# Work over a page with Rasmus

The page is how Rasmus and his assistant look at the same thing. He selects a part, a connection or a flow step and presses "Ask about this" (or A). That copies a message that names the page, the part and the command that reads it. He pastes it and adds his question.

When a message starts "In the Blueprint page …":

1. Run the command it gives: `blueprint show <page>.html <id>`. It prints the part with its connections, its flow steps, what was said about it earlier and the code it cites. `blueprint show <page>.html` prints the whole page in short. Answer from what it prints: the page can have changed since you last read it.
2. Answer against the code. Open the cited lines in the repository, and read further when the question goes past them. Say what the code shows, what the page claims, and where the two differ. If the page is wrong, say so and correct it.
3. Keep what was said on the page, so that the next session starts from it:
   - `blueprint note <page>.html "Does the mobile app keep its session cookie?" --status open --refs mobile-app` for a question nobody has answered.
   - `--status decided --detail "..."` for what Rasmus decided, with the reason. `--status dropped` for what was ruled out. A note with the same title replaces the old one.
   - `--url <address>` with the title for a source that was read.

   Record a decision only when Rasmus made it. Your own view is an answer.
4. When the answer changes the architecture, change the page. Quick: `blueprint sketch "the objection or the decision" --from <page>.html` revises a proposal. Deep: edit the model beside the page, then check and render it. Tell Rasmus to reload, and say what changed.

The Discussion card in the page's panel shows the open questions, the decisions and what was read, each linked to its parts. The comparison page shows them for every option.
