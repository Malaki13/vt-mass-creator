#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate a large set of varied, credible comments for VirusTotal files."""

import random
from pathlib import Path

RNG = random.Random(4242)

OS = [
    "Windows 11 24H2", "Windows 11 23H2", "Windows 11 22H2",
    "Windows 10 22H2", "Windows 10 LTSC 2021", "Windows Server 2022",
    "a clean Windows 11 VM", "a Windows 10 VM", "a Windows 11 sandbox",
]
DURATION = [
    "a few minutes", "10 minutes", "20 minutes", "half an hour",
    "an hour", "a couple of hours", "a full afternoon", "a whole day",
]
TOOLS = [
    "Procmon", "Process Explorer", "Autoruns", "Wireshark", "TCPView",
    "a sandbox", "Defender", "Sysmon", "Process Monitor", "API Monitor",
]
OBS = [
    "no registry persistence", "no outbound connections", "no dropped files",
    "no suspicious child processes", "no crash", "the UI loaded normally",
    "CPU usage stayed low", "memory usage stayed stable",
    "no unexpected writes outside its folder", "no service was installed",
    "no scheduled task was created", "no elevated prompt appeared",
    "the process exited cleanly", "no hidden window appeared",
    "no unusual DNS queries", "no file was written to Temp",
    "no network traffic after startup", "the app responded normally",
    "no suspicious modules were loaded", "no crash dump was generated",
    "no persistence mechanism was added", "the window closed cleanly",
    "no unusual handle was left open", "no log entry looked abnormal",
]
ARTIFACTS = [
    "registry keys", "dropped files", "services", "scheduled tasks",
    "network connections", "child processes", "Temp files", "startup entries",
    "mutexes", "elevated prompts", "hidden windows", "DNS queries",
]
USAGE = [
    "the main screen opened normally", "the menus worked as expected",
    "the settings dialog opened fine", "the app stayed responsive",
    "the process used little CPU", "the memory footprint was stable",
    "the window resized normally", "no error dialog appeared",
    "the app closed without hanging", "the first launch was quick",
    "the second launch was also clean", "the app recovered from focus changes",
]
STATIC = [
    "the imports look normal for a desktop app",
    "no packed sections were obvious",
    "the resources look ordinary",
    "the section layout looks standard",
    "no suspicious URL strings stood out",
    "the strings are consistent with a test app",
    "the PE layout looks conventional",
    "no unusually high entropy section was noticed",
    "the overlay looks small and normal",
    "the entry point looks typical for this kind of build",
]
FP_REASON = [
    "the signature looks generic", "the heuristic is probably too broad",
    "the rule seems to match a common pattern", "the detection is isolated",
    "the engine likely flagged a packer pattern", "the sample behaves normally",
    "the detection does not reproduce in a sandbox", "the ratio is only 1/70",
    "the flagged engine is often noisy on installers",
    "the same hash is clean on my side",
]
ENGINE = [
    "one engine", "a single engine", "one AV", "the flagged engine",
    "that one heuristic", "only one vendor",
]
QUESTIONS = [
    "Anyone else only seeing one engine flag this?",
    "Is the single detection reproducible for you?",
    "Curious whether the flagged engine is a heuristic.",
    "Can someone confirm the hash? Mine looks clean.",
    "Did anyone see any network traffic after launch?",
    "Is this detection still present after a rescan?",
    "Anyone tested it on Windows 10 as well?",
    "Could this be an installer-related false positive?",
    "Does the detection change after a few days?",
    "Anyone else getting 1/70 on this build?",
    "Has the sample been reanalyzed recently?",
    "What does the flagged engine report exactly?",
    "Is the file signed, or is that unrelated here?",
    "Anyone ran it with Procmon for a longer session?",
    "Does it create any service on first launch?",
    "Anyone see a difference between first and second run?",
]
FR_OBS = [
    "aucun comportement suspect", "aucune connexion sortante",
    "aucun fichier déposé", "aucun crash", "aucune persistance",
    "aucune tâche planifiée", "aucun service installé",
    "l'interface s'ouvre normalement", "le processus se ferme proprement",
    "aucune activité réseau après le démarrage", "aucune clé de registre inhabituelle",
    "la consommation CPU reste faible", "la mémoire reste stable",
    "aucune fenêtre cachée", "aucun accès élevé demandé",
]
FR_START = [
    "Testé sur {os} pendant {duration}",
    "Lancé sur {os} pendant {duration}",
    "Utilisé sur {os} pendant {duration}",
    "Essayé sur {os} pendant {duration}",
    "Exécuté dans {tool} sur {os}",
    "Vérifié avec {tool} sur {os}",
]


def add(pool: list[str], text: str) -> None:
    text = " ".join(text.split())
    if text and text not in pool:
        pool.append(text)


def build() -> list[str]:
    comments: list[str] = []
    seen: set[str] = set()

    def push(text: str) -> None:
        text = " ".join(text.split()).strip()
        if text and text not in seen:
            seen.add(text)
            comments.append(text)

    # --- very short verdicts -------------------------------------------
    shorts = [
        "Clean here.", "Looks fine.", "No issues on my side.", "Harmless for me.",
        "Nothing suspicious.", "Runs fine.", "All good.", "No problems.",
        "Seems clean.", "Fine in my VM.", "Clean on Win11.", "Clean on Win10.",
        "No alerts here.", "Nothing weird.", "Works normally.", "Looks harmless.",
        "No crash.", "No persistence.", "No dropped files.", "No network calls.",
        "Quiet process.", "Normal behaviour.", "Looks like a FP.", "Probably harmless.",
        "Clean in my sandbox.", "No suspicious activity.", "Nothing to report.",
        "Tested, clean.", "Quick test, clean.", "No issue at all.",
        "Clean from my side.", "No findings.", "Nothing abnormal.",
        "Looks legitimate.", "Behaves normally.", "No red flags.",
        "All normal.", "Runs as expected.", "No visible side effects.",
        "Fine on first run.", "Fine on second run.", "Clean after reboot.",
        "Still clean after rescan.", "No change after rescan.",
        "Single detection, likely FP.", "One engine, likely FP.",
        "Only one flag, looks like FP.", "Nothing suspicious in my run.",
        "No suspicious strings noticed.", "Clean in a fresh VM.",
    ]
    for s in shorts:
        push(s)

    # --- casual ---------------------------------------------------------
    casual_templates = [
        "Ran it on {os} for {duration}, {obs}.",
        "Tried it on {os} for {duration}; {obs}.",
        "Installed it on {os} and used it for {duration}, {obs}.",
        "Gave it a spin on {os} for {duration}; {obs}.",
        "Used it for {duration} on {os}, {obs}.",
        "Quick run on {os}: {obs}.",
        "No {artifact} after a quick run on {os}.",
        "Launched it twice on {os}, {obs}.",
        "Tested it for {duration} on {os}, {obs}.",
        "Works fine on {os}; {obs}.",
        "No {artifact} seen on {os}.",
        "Ran it from a USB stick on {os}, {obs}.",
        "Moved it to another folder and ran it on {os}, {obs}.",
        "Opened it on {os} for {duration}, {obs}.",
        "No {artifact} after the first launch on {os}.",
        "Second launch on {os} was also clean; {obs}.",
        "Ran it as a normal user on {os}, {obs}.",
        "Ran it elevated on {os}, {obs}.",
        "Used it for {duration}, {obs}.",
        "No {artifact} during {duration} on {os}.",
    ]
    for template in casual_templates:
        for _ in range(6):
            push(template.format(
                os=RNG.choice(OS), duration=RNG.choice(DURATION),
                obs=RNG.choice(OBS), artifact=RNG.choice(ARTIFACTS),
            ))

    # --- technical ------------------------------------------------------
    tech_templates = [
        "Executed in {tool} on {os}; {obs}.",
        "{tool} on {os} showed {obs}.",
        "No {artifact} observed with {tool} on {os}.",
        "Dynamic run in {tool}: {obs}.",
        "Monitored it with {tool} for {duration} on {os}; {obs}.",
        "Started it under {tool} on {os}, {obs}.",
        "Captured traffic with {tool} on {os}; {obs}.",
        "Compared first and second run with {tool}, {obs}.",
        "Ran it with {tool} and checked {artifact}: {obs}.",
        "Tested in {tool} on {os}; {obs}.",
        "No {artifact} after {duration} under {tool}.",
        "Checked the process tree with {tool} on {os}; {obs}.",
        "File activity in {tool} was ordinary; {obs}.",
        "Registry activity in {tool} was limited; {obs}.",
        "Network activity in {tool} was quiet; {obs}.",
        "Observed with {tool} on {os} for {duration}: {obs}.",
        "Ran it in a clean snapshot with {tool}; {obs}.",
        "Ran it with a standard user and with admin rights; {obs}.",
        "No {artifact} in the first {duration} on {os}.",
        "Re-ran it after a reboot on {os}; {obs}.",
    ]
    for template in tech_templates:
        for _ in range(6):
            push(template.format(
                os=RNG.choice(OS), duration=RNG.choice(DURATION),
                tool=RNG.choice(TOOLS), obs=RNG.choice(OBS),
                artifact=RNG.choice(ARTIFACTS),
            ))

    # --- false positive reasoning --------------------------------------
    fp_templates = [
        "{ratio} looks like a heuristic false positive; {reason}.",
        "Only {engine} flags it; {reason}.",
        "The single detection seems inconsistent with the other engines; {reason}.",
        "Detection ratio is {ratio}; {reason}.",
        "I would treat {ratio} as a false positive because {reason}.",
        "{engine} flags it but {reason}.",
        "One detection out of {n} engines is easy to explain: {reason}.",
        "The verdict looks like an isolated FP; {reason}.",
        "With {ratio}, this looks more like a noisy signature than a real threat.",
        "The flagged detection does not match the behaviour I observed; {reason}.",
        "Looks like a classic single-engine FP; {reason}.",
        "I checked the file after the detection; {reason}.",
        "The detection may come from a generic heuristic; {reason}.",
        "Nothing in the sandbox supports the single detection; {reason}.",
    ]
    ratios = ["1/70", "1/71", "1/69", "1/68", "1/72", "one detection"]
    for template in fp_templates:
        for _ in range(5):
            push(template.format(
                ratio=RNG.choice(ratios), engine=RNG.choice(ENGINE),
                reason=RNG.choice(FP_REASON), n=RNG.choice(["70", "71", "69", "72"]),
            ))

    # --- usage reports -------------------------------------------------
    usage_templates = [
        "Used it for {duration}; {usage}.",
        "Launched it {n} times on {os}, {usage}.",
        "Tested the main features for {duration}; {usage}.",
        "Opened and closed it several times on {os}; {usage}.",
        "Ran it for {duration} on {os}; {usage}.",
        "First launch on {os}: {usage}.",
        "Second launch on {os}: {usage}.",
        "Used it normally for {duration}, {usage}.",
        "Started it {n} times in a row, {usage}.",
        "Left it open for {duration} on {os}; {usage}.",
        "Used it alongside other apps on {os}; {usage}.",
        "Ran it after a fresh boot on {os}; {usage}.",
        "Ran it with a standard user profile; {usage}.",
        "Ran it from a different working directory; {usage}.",
        "Tested it for {duration} and then rebooted; {usage}.",
        "Ran it with the network disabled; {usage}.",
    ]
    for template in usage_templates:
        for _ in range(6):
            push(template.format(
                os=RNG.choice(OS), duration=RNG.choice(DURATION),
                usage=RNG.choice(USAGE), n=RNG.choice(["2", "3", "4", "5"]),
            ))

    # --- static / analyst ----------------------------------------------
    static_templates = [
        "Static review: {static}.",
        "Quick PE review: {static}.",
        "Nothing unusual in the headers: {static}.",
        "Checked the sections and imports: {static}.",
        "No obvious packing: {static}.",
        "The binary looks ordinary: {static}.",
        "Strings review: {static}.",
        "Resource review: {static}.",
        "Entry point and imports: {static}.",
        "No high-entropy section stood out; {static}.",
        "The overlay is small and looks normal; {static}.",
        "The import table is consistent with a desktop app; {static}.",
        "No suspicious URL strings; {static}.",
        "The PE layout looks standard; {static}.",
        "Static and dynamic checks agree: {static}.",
    ]
    for template in static_templates:
        for _ in range(4):
            push(template.format(static=RNG.choice(STATIC)))

    # --- French ---------------------------------------------------------
    fr_templates = [
        "{start}, {obs}.",
        "{start} : {obs}.",
        "{start} et {obs}.",
        "Aucun problème sur {os} pendant {duration} : {obs}.",
        "Testé sur {os}, {obs}.",
        "Lancé plusieurs fois sur {os}, {obs}.",
        "Vérifié avec {tool} sur {os} : {obs}.",
        "Rien de suspect sur {os} : {obs}.",
        "Le seul moteur qui le détecte ressemble à un faux positif.",
        "Détection isolée, probable faux positif.",
        "Le fichier se comporte normalement sur {os}.",
        "Aucune activité réseau après le lancement sur {os}.",
        "Aucune persistance observée sur {os}.",
        "Le processus se ferme proprement sur {os}.",
        "Test rapide sur {os}, {obs}.",
    ]
    for template in fr_templates:
        for _ in range(4):
            push(template.format(
                start=RNG.choice(FR_START), os=RNG.choice(OS),
                duration=RNG.choice(DURATION), tool=RNG.choice(TOOLS),
                obs=RNG.choice(FR_OBS),
            ))

    # --- questions ------------------------------------------------------
    for q in QUESTIONS:
        push(q)
    for _ in range(30):
        push(RNG.choice(QUESTIONS))

    # --- hash / verification -------------------------------------------
    hash_templates = [
        "Hash checked, {ratio} on my side.",
        "Same hash here, {ratio}.",
        "Confirmed the hash, looks clean.",
        "SHA matches, detection unchanged.",
        "Hash verified, no new detections after rescan.",
        "Checked the hash twice; same result.",
        "Same file, same single detection.",
        "Hash matches, behaviour is normal.",
        "Rescanned the hash, still {ratio}.",
        "Hash confirmed, no additional flags.",
        "Same hash on my machine, clean run.",
        "Verified the hash before testing.",
    ]
    for template in hash_templates:
        for _ in range(4):
            push(template.format(ratio=RNG.choice(ratios)))

    # fill to 500 with short unique variants if needed
    fillers = [
        "Clean after a second look.", "Still looks harmless.",
        "No change after another run.", "Nothing new to report.",
        "Rechecked it, still clean.", "Same result after a reboot.",
        "Same result in a new VM.", "Same result on another machine.",
        "Tested again, no issues.", "Re-ran it, no issues.",
        "No new findings.", "No new detections.",
        "No side effects noticed.", "No side effects after reboot.",
        "Clean on a fresh profile.", "Clean on a second machine.",
    ]
    i = 0
    while len(comments) < 500:
        push(fillers[i % len(fillers)] + ("" if i < len(fillers) else f" ({i})"))
        i += 1

    return comments[:500]


def main() -> None:
    comments = build()
    assert len(comments) == 500, len(comments)
    path = Path("comments_500.txt")
    path.write_text(
        "# 500 commentaires uniques et variés - un par ligne\n"
        + "\n".join(comments) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(comments)} unique comments to {path.resolve()}")
    for line in comments[:15]:
        print("-", line)


if __name__ == "__main__":
    main()
