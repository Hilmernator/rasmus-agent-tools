---
name: youtube-research
description: Researcha aktuella YouTube-videor kring en teknikidé eller textdump och omsätt belagda fynd i en brief för vinkel, engelskt manus, titel, thumbnail, talking head och animation. Använd för trendspaning, jämförelse av videoresultat och research före youtube-story-script i YouTube-strategiprojektet.
---

# YouTube-research som grund för produktion

Arbeta från skaparens ämne och eget material till ett spårbart beslutsunderlag. En lista med populära videor är inte en färdig leverans. Skilj verifierad observation, kreatörens påstående, vår hypotes och egna experiment. Beskriv aldrig offentlig statistik som bevis för varför något lyckades.

## Projekt och inriktning

Projektroten är `/Users/rasmushilmersson/youtube/strategy`. Läs dess `CONTEXT.md`, `STATUS.md`, `research/README.md` och relevant videobrief. Använd projektets datainsamlare `tools/youtube-research/research.mjs`; använd kommandona nedan från projektroten. Om projektet saknas, säg det och utför en tydligt avgränsad webbresearch utan att påstå att datainsamlaren körts.

Kända förutsättningar: engelska manus, normalt 5–8 minuter och oftast under tio; skaparen kan göra talking head och animationer och vill prata teknik. Slutlig nisch och primär tittare är inte beslutade. Anta inte att AI-nyheter är rätt ämne bara för att de får stora visningstal. Anpassa researchen till den egna erfarenheten, förklaringen eller demonstrationen.

Om användaren har en idé eller textdump: formulera tittarens problem, videons möjliga löfte och vad skaparen faktiskt kan visa. Saknas ämne, ställ en kort fråga och gör under tiden en uttalat preliminär teknikspaning. Be inte om en färdig kanalstrategi. Dokumentera tillfälliga antaganden.

## Samla i två steg

1. Välj 3–5 engelska sökningar: samma problem, tittarens önskade resultat och ett närliggande berättarformat. Använd offentliga ämnesord; skicka inte interna arbetsplatsnamn eller privat råtext till YouTube.
2. Kör `search` för senaste månaden. Vid behov komplettera med senaste veckan för färska fynd och senaste året för äldre formatreferenser. Blanda inte årsfynd med bevis för vad som är aktuellt nu.
3. Läs kandidaternas titlar, metadata och källor. Sålla bort ämnesglidning, andra språk när de inte är relevanta, livesändningar, rena produktannonser och format som är orimliga för vår produktion. Ange skäl; sortera inte endast på visningar.
4. Välj högst tre relevanta kandidater åt gången, helst från olika kanaler. Kör `inspect` för thumbnails, transkriptförsök, kanaljämförelser och rekommendationer. Inspektera även ett relevant vanligt/svagt resultat som motexempel när det finns, inte bara topparna.
5. Följ ett relevant rekommendations- eller kanalspår vidare med `search --id`. Spara föräldervideon i analysen eftersom ett explicit seed inte automatiskt bär den tidigare upptäcktsvägen. Stanna när nästa fynd upprepar samma princip eller när du nått cirka 30 kandidater. Det är en arbetsbudget, inte ett krav att fylla.

```sh
node tools/youtube-research/research.mjs search --query "ämne problem" --query "önskat resultat" --window month
node tools/youtube-research/research.mjs inspect --input research/runs/KÖRNING/snapshot.json --id VIDEO_ID
node tools/youtube-research/research.mjs search --id VIDEO_ID
node tools/youtube-research/research.mjs refresh --input research/runs/KÖRNING/snapshot.json
```

Kommandot skriver en ny körningsmapp med `snapshot.json` och `report.md`. `--out NY_MAPP` ger valfri målplats; en befintlig mapp skrivs inte över. Vid saknade beroenden, följ `tools/youtube-research/README.md`. Använd inte cookies, inloggning, proxyrotation eller blockeringens kringgående. Verktyget har avgränsade anrop och stoppar nättrafik efter 403/429. Vid fel, behåll delresultat och redovisa vad som saknas. Webbsökning eller synlig YouTube-sida kan ge kompletterande belägg, men kalla inte sökmotorns cache för aktuell avläsning.

## Avgör vad vi faktiskt vet

- **Räckvidd:** exakta observerade visningstal tillsammans med publiceringstid och avläsningstid. Nyligen publicerad och många visningar är en kandidat, inte ett bevis på dagens tillväxt.
- **Momentum:** kräver minst två avläsningar av samma ID. `refresh` återbesöker även videor som försvunnit ur sökningen. Verktyget beräknar visningar per timme endast med 24–168 timmar mellan mätningarna; redovisa hela intervallet. Det är en operativ arbetsregel. Livstidssnitt per dygn är något annat.
- **Relativt resultat:** kvoten mot kanalens baslinje är preliminär. Kontrollera jämförelse-ID:n, ålder, längd och verkligt format/ämne. Verktygets åldersintervall återskapar inte historiska visningar vid samma videoålder. Saknas minst fem användbara jämförelser eller är medianen noll, förblir kvoten okänd. Räkna om och lista nytt urval om den redaktionella granskningen utesluter videor.
- **Tittarbeteende:** CTR, retention och trafikkällor är okända utan egen eller delad analysdata. Inga påhittade betyg på retention, viralitet eller ”algoritmpoäng”.

Det finns ingen universell gräns för ”mycket views”. Jämför absolut räckvidd, aktuellt mätintervall, rimlig kanalbaslinje och relevans var för sig. Märk osäkerhet och alternativa förklaringar, till exempel stor befintlig publik eller ett aktuellt produktsläpp.

## Granska material innan du drar slutsatser

Öppna lokalt hämtade thumbnails med bildverktyg. Analysera titel och bild som ett par: gemensamt löfte, huvudmotiv, läsbarhet i liten storlek, text, kontrast och vad som väcker en begriplig fråga. En thumbnail-URL räcker inte för visuella slutsatser.

Läs transkriptfilen om hämtningen lyckades. Ange språk, om texten är automatisk/okänd och vilken del du läst. Undersök konkret öppning, bakgrund, förklaringssteg, vändpunkter, bevis och avslut. Återge principer med egna ord; kopiera inte manus eller särpräglade uttryck.

Transkriptförsök kan misslyckas. Då är manusanalysen av den referensen **inte genomförd**. Fortsätt med metadata och visuellt granskade thumbnails och märk ett föreslaget manusupplägg som vår egen hypotes. Om tillgänglig browser används för video eller synligt transkript, följ browser-skillen och ange exakt vad som granskats. Beskriv inte redigering, animation, ljud eller kroppsspråk utifrån text. Använd tidskoder endast från faktiskt tillgängligt och granskat material.

Låt maskinrapportens `evidence`-fält stå för maskinens åtkomst. Dokumentera faktisk mänsklig/agentbaserad granskning separat i researchbriefen; ”hämtat” betyder inte ”granskat”.

## Omsätt fynd till den egna videon

Utveckla högst tre egna titel/thumbnail-par på engelska. Varje par måste kunna infrias med skaparens eget material. Ange vilket fynd som inspirerar principen och vad som är vår nya tillämpning. Kopiera inte en referensbild eller byt bara några ord i dess titel.

För manusbriefen, föreslå:

- En huvudsaklig tittarfråga och tydlig payoff.
- En öppning som visar ett verkligt problem, överraskande resultat eller begriplig teknisk fråga.
- En förenklad hjälteresa när egna händelser bär den: mål → hinder → försök → förändring → resultat/lärdom. Vid ren förklaring fungerar fråga → undersökning → insikt.
- Talking head för egen erfarenhet, val, osäkerhet och slutsats. Animation när tittaren behöver se tillstånd, tid, flöden eller samband. Skärmdemo när ett verkligt resultat behöver bevisas. Detta är våra produktionsval, inte något metadata säger att andra videor gör.
- Vad som ska utelämnas för att hålla berättelsen begriplig och oftast under tio minuter.

Prioritera principer som går att överföra till vårt material framför ytliga likheter. Ett intressant bygge eller ett konkret tekniskt missförstånd kan passa bättre än ett trendämne utan egen evidens.

## Leverans och överlämning

Använd projektets `templates/research-brief.md` som stöd. Spara vald videos brief i `videos/<id>/research.md`; före val av video sparas spaningen under `research/runs/`. Leverera en tydlig rekommendation med:

1. Ämne, tittare/antagande, sökdatum, sökspår och avgränsning.
2. En kortlista med video-URL, datum, observerade tal och exakt granskat underlag, plus relevanta motexempel.
3. En tabell: **observation + källa → möjlig förklaring → egen tillämpning → osäkerhet**.
4. Rekommenderat titel/thumbnail-par, manusets berättelsebåge och fördelning mellan talking head, animation och demonstration. Engelska publika formuleringar, svensk förklaring.
5. Fakta och egna bevis som saknas, samt nästa konkreta steg. Ange när en ny avläsning behövs; påstå inte att en schemalagd bevakning är installerad.

Överlämna briefen till `youtube-story-script` när ett manus ska skrivas. Researchen styr vinkeln och vad som behöver visas, men får inte skriva om vad skaparen faktiskt upplevt. Uppdatera projektets `STATUS.md`. Var tydlig med skillens utförda analys respektive verktygets mekaniska insamling.
