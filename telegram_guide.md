Il chat ID è l’identificatore numerico (o lo username del canale) della chat dove il bot deve inviare i messaggi.
Può essere:

utente (DM): numero positivo (es. 123456789)

gruppo/supergruppo: numero negativo (es. -1001234567890)

canale: @username_del_canale oppure numero negativo -100...

Come ottenerlo
A) Chat privata (DM) con te

Su Telegram, cerca il tuo bot e premi Start (il bot non può scriverti finché non lo fai).

Sul server (o da PC), esegui:

TOKEN="123456:ABCDEF..."   # il tuo token
curl -s "https://api.telegram.org/bot$TOKEN/getUpdates" | jq


Cerca message.chat.id nell’output: quello è il chat_id.
(In alternativa, scrivi a @userinfobot: ti mostra il tuo user ID che coincide con il chat_id per DM.)

B) Gruppo / Supergruppo

Aggiungi il bot al gruppo.

Invia un messaggio nel gruppo (meglio menzionando il bot se ha la “privacy” ON).

Esegui:

curl -s "https://api.telegram.org/bot$TOKEN/getUpdates" | jq


Prendi message.chat.id: sarà negativo, tipo -1001234567890. Copialo come stringa (con il segno meno).

Nota: se il bot ha “Group Privacy” attiva, legge solo messaggi che lo menzionano o sono reply. Puoi disattivarla da @BotFather → /mybots → Bot Settings → Group Privacy → Turn off.

C) Canale

Aggiungi il bot come amministratore del canale (permesso “pubblica messaggi”).

Puoi usare @username_del_canale direttamente come chat_id oppure recuperare l’ID numerico:

posta qualcosa sul canale, poi:

curl -s "https://api.telegram.org/bot$TOKEN/getUpdates" | jq


e prendi channel_post.chat.id (sarà -100...).

Test rapido

Dopo aver messo token e chat_id in /alerts, usa il pulsante “Invia test”.
Se non arriva:

verifica che tu abbia premuto Start in DM, o che il bot sia nel gruppo/canale,

per gruppi: prova a menzionare il bot oppure disattiva la privacy nei gruppi (vedi sopra).
