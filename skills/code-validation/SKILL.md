---
name: code-validation
description: Granska ocommittade kodändringar med git diff inför commit, utan att ändra kod. Använd vid code validation, pre-commit review eller begäran att hitta fel i staged och unstaged ändringar. Ger prioriterade fynd och åtgärdsförslag i ord; utför inga rättningar.
---

# Code Validation

Hitta konkreta problem före commit. Användaren kan ha testat ändringarna och uppleva att allt fungerar; granska ändå kontrakt, normal användning och relevanta kantfall. Att något ännu inte testats är inte i sig ett bevis på ett fel.

## Avgränsning

- Analysera endast. Ändra inte kod, tester, konfiguration eller Git-index. Gör ingen commit, stash, reset, automatisk formatering eller rättning.
- Ge åtgärdsförslag i ord, utan patchar eller ersättningskod. Skriv rapporten i svaret om användaren inte bett om en fil.
- Granska ocommittade ändringar i det avsedda repot. Läs omgivande kod, anropare, typer och tester när det behövs för att bedöma ändringen; utöka inte uppdraget till en allmän repo-audit.
- Följ användarens språk; svenska är standard.

## Underlag

1. Läs tillämpliga repo-instruktioner och fastställ reporoten med `git rev-parse --show-toplevel`. Om arbetsmappen inte är ett Git-repo, lokalisera användarens avsedda repo eller fråga efter sökvägen. Initiera inte Git.
2. Läs `git status --short --untracked-files=all`, `git diff --no-ext-diff --no-textconv` och `git diff --cached --no-ext-diff --no-textconv`. Både unstaged och staged ändringar ingår om användaren inte avgränsat granskningen.
3. Granska även relevanta nya, ospårade källfiler: de syns inte i vanlig `git diff`. Lägg inte till dem i index. Hantera namnbyten, borttagningar och eventuella konflikter uttryckligen. Läs inte genererade filer, binärer eller hemligheter slentrianmässigt; ange betydelsefulla granskningsluckor.
4. Om samma fil har både staged och unstaged ändringar, skilj indexversionen från arbetskopian. Kontrollera indexversionen med `git show :sökväg` när skillnaden påverkar ett fynd. Anta inte att allt i arbetskopian kommer med i nästa commit.
5. Följ ändrade importvägar, API-kontrakt, datamodeller och anrop tills ett möjligt fel antingen styrks eller kan avfärdas. Hänvisa till den version och de rader som faktiskt granskats.

Om inget har ändrats, säg det. Om diffen är för stor eller vissa filer inte går att granska, redovisa omfattningen och luckorna i stället för att hävda en fullständig granskning.

## Granskningsprioriteringar

1. **Kritiska stoppfel:** krascher, importfel, brutna API-kontrakt, runtime-fel, datamodeller som inte stämmer överens och antaganden som bryter normal användning.
2. **Oväntat beteende:** logikfel, kantfall, felaktiga standardvärden, tysta fel och bristande felhantering.
3. **Kodkvalitet:** duplicering, onödig komplexitet, missvisande namn och filer eller funktioner med för många ansvar. Rapportera konkreta underhållsproblem, inte personlig stilsmak.
4. **Prestanda:** onödigt upprepat dyrt arbete, hantering av stora filer och blockerande operationer som påverkar faktisk API- eller MVP-användning. Beskriv utlösande belastning; hitta inte på mätresultat eller föreslå spekulativ optimering.

Prioriteten anger granskningsordning; fyndens allvar bestäms av konsekvensen. Ett prestandafel som gör normal användning omöjlig kan vara ett stoppfel.

## Belägg och verifiering

- Lyft fynd som orsakas eller blottläggs av ändringarna och har ett konkret felscenario. Skilj bekräftade fel från frågor och osäkerheter. Kontrollera skydd i omgivande kod innan ett fel rapporteras.
- Statisk analys är standard. Kör endast befintliga, relevanta kontroller om du har fastställt att de inte ändrar arbetsfiler, index, snapshots, databaser eller externa system. Installera inget och kör inte auto-fix. Om säker verifiering saknas, redovisa det i rapporten.
- Hävd inte att ett test har körts, att ett fel reproducerats eller att all kod fungerar utan belägg. Ingen funnen bugg är ingen garanti om felfrihet.

## Svar

Börja med fynden, sorterade efter allvar. Varje fynd innehåller:

- **Allvar och konkret rubrik:** kritisk, hög, medel eller låg.
- **Plats:** fil och kort radreferens, gärna klickbar. Ange indexversion/staged eller arbetskopia om det spelar roll. För borttagen kod: ange att referensen gäller den gamla versionen.
- **Problem och konsekvens:** vad som händer, vilket scenario som utlöser det och varför det spelar roll.
- **Föreslagen rättning:** en kort beskrivning i ord.

Slå ihop fynd med samma grundorsak. Lägg eventuella öppna frågor efter fynden. Avsluta kort med granskad omfattning, utförda kontroller och betydelsefulla begränsningar.

Om inga kritiska fel hittats, skriv uttryckligen **”Inga kritiska problem identifierades i de granskade ändringarna.”** Om inga fynd alls finns, säg det utan att fylla ut med påhittade förbättringar. Använd motsvarande formulering på användarens språk.
