# Tripline, explained simply

No technical words. Five pictures, five minutes. (For the technical version, see [ARCHITECTURE.md](ARCHITECTURE.md).)

## 1. The problem

![An AI assistant obeys a note an attacker hid in an email](img/explained/1-problem.svg)

Think of an AI assistant (Claude, ChatGPT, Cursor) as a very obedient new employee. It does what any piece of text tells it to, even a note a stranger slipped into an email, a web page or a document. It also has the keys to your tools: your email, your files, your code, sometimes your bank.

So an attacker doesn't need to hack your computer. They only need the AI to *read* their note.

## 2. What Tripline is

![Tripline is a guard between the AI assistant and its tools](img/explained/2-guard.svg)

Tripline is a **security guard standing between the AI and its tools**. Every request the AI sends ("send this email") and every answer that comes back ("here's the web page") passes through the guard first. For each one, the guard either lets it through, blocks it, or asks you.

You don't change the AI or the tools. One command puts the guard in place.

## 3. The guard's five jobs

![The five jobs of the Tripline guard](img/explained/3-five-jobs.svg)

1. **Checks IDs.** The first time a tool shows up, the guard records exactly what it is. If the tool later changes what it says it does, it's blocked. A tool can't be friendly on day one and turn evil on day ten.
2. **Spots tricks.** Notes like "ignore your previous instructions" are held back. Attackers can reword their notes, so this is only a first filter.
3. **Follows your secrets.** This is the most important job. See the next picture.
4. **Asks you first.** Paying money, unlocking something, or sending to an address that came from a stranger's text pops up a question in your app: "Allow this?" You decide.
5. **Locks the room.** A tool you don't trust can run in a locked room where it can't see your personal files. Tested on macOS.

## 4. Following your secrets

![Tripline follows a secret and stops it leaving, even when it is disguised](img/explained/4-follow-secrets.svg)

When the AI reads a password or a key, the guard quietly remembers it. If that same secret later tries to leave through any tool, the guard stops it, even when it's disguised (scrambled, reversed or split into pieces) and even when it leaves through a different tool than the one it came from.

The guard doesn't need to understand the attacker's note. It only needs to see your secret heading out the door.

## 5. Does it work?

![Data theft stopped in 1,054 public attacks: 1.7% by spotting tricks, 100% by following secrets](img/explained/5-proof.svg)

We replayed 1,054 publicly known attacks against Tripline, pretending the AI had already fallen for every one of them:

- Only **spotting tricks** stopped 1.7% of the attempts to steal data.
- **Following your secrets** stopped all of them.

That's the main lesson: you can't rely on spotting the attacker's words, because words can always be changed. You have to watch where your data goes. We also attacked Tripline ourselves four times before release and fixed every weakness we found.

## What it can't do yet

- **Harm without theft.** If a note tells the AI to do something harmful without stealing anything ("delete this file"), the guard asks you only for high-risk actions like payments and unlocking. Strict mode asks before every change.
- **Secrets retold in plain sentences.** If the AI describes your secret in its own words instead of copying it, or chops it into very tiny pieces (under 6 characters), the guard may not notice.
- **Locked room on Linux and Docker.** The locked room is tested on macOS; on Linux and Docker it hasn't been tried on real machines yet.

## Try it

```bash
tripline demo --unprotected   # watch 7 attacks succeed
tripline demo                 # watch Tripline stop every one
```
