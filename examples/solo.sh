#!/bin/sh
# Fixed synthetic message only. All working state and backups disappear with the container.
set -eu
export PYTHONPATH=/protocol/reference/python
umask 077
TASK_DIR=$(mktemp -d /tmp/otherwise-solo-demo.XXXXXX)
trap 'rm -rf "$TASK_DIR"' EXIT HUP INT TERM
echo "Create and arm two fixed synthetic Capsules at t=1000."
python -m otherwise_solo.cli init-custodian --db "$TASK_DIR/custody.sqlite" > "$TASK_DIR/custodian-public.json"
python -m otherwise_solo.cli init-identities --directory "$TASK_DIR/keys"
cp -R "$TASK_DIR/keys" "$TASK_DIR/independent-backup"
for NAME in cancel release; do
  python -m otherwise_solo.cli create --identities "$TASK_DIR/keys" --custodian-public "$TASK_DIR/custodian-public.json" --out "$TASK_DIR/$NAME.json"
  python -m otherwise_solo.cli act arm --file "$TASK_DIR/$NAME.json" --creator "$TASK_DIR/keys/creator.json" --endpoint "file:$TASK_DIR/custody.sqlite" --synthetic-now 1000
done
rm -r "$TASK_DIR/keys"
cp -R "$TASK_DIR/independent-backup" "$TASK_DIR/restored-client"
python -m otherwise_solo.cli act checkin --file "$TASK_DIR/cancel.json" --creator "$TASK_DIR/restored-client/creator.json" --endpoint "file:$TASK_DIR/custody.sqlite" --synthetic-now 1060
echo "Renew the release Capsule at t=1060; its new deadline is 1120, grace ends at 1130."
python -m otherwise_solo.cli act checkin --file "$TASK_DIR/release.json" --creator "$TASK_DIR/restored-client/creator.json" --endpoint "file:$TASK_DIR/custody.sqlite" --synthetic-now 1060
python -m otherwise_solo.cli act status --file "$TASK_DIR/cancel.json" --endpoint "file:$TASK_DIR/custody.sqlite" --synthetic-now 1061
python -m otherwise_solo.cli act disarm --file "$TASK_DIR/cancel.json" --creator "$TASK_DIR/restored-client/creator.json" --endpoint "file:$TASK_DIR/custody.sqlite" --synthetic-now 1075
echo "Advance the test clock into grace at t=1121, then past grace at t=1131."
python -m otherwise_solo.cli act status --file "$TASK_DIR/release.json" --endpoint "file:$TASK_DIR/custody.sqlite" --synthetic-now 1121
python -m otherwise_solo.cli act release --file "$TASK_DIR/release.json" --endpoint "file:$TASK_DIR/custody.sqlite" --synthetic-now 1131
echo "Explicitly export the committed recipient package."
python -m otherwise_solo.cli act export --file "$TASK_DIR/release.json" --endpoint "file:$TASK_DIR/custody.sqlite" --synthetic-now 1132
python - "$TASK_DIR" <<'PY'
import sys
from pathlib import Path
from otherwise_solo.codec import parse,canonical,b64
r=Path(sys.argv[1]); state=parse((r/'release.json').read_bytes())
(r/'archive.json').write_bytes(canonical(state['archive']))
(r/'pins.json').write_bytes(canonical(state['pins']))
recipient=parse((r/'restored-client/recipient.json').read_bytes())['secret']
(r/'php-input.json').write_bytes(canonical({'input':b64((r/'archive.json').read_bytes()),'pins':state['pins'],'options':{'recipient':recipient}}))
PY
python -m otherwise_solo.cli verify --file "$TASK_DIR/archive.json" --pins "$TASK_DIR/pins.json" --recipient "$TASK_DIR/restored-client/recipient.json"

echo "Independently verify and decrypt the new export with PHP (no Python oracle)."
php -d ffi.enable=true reference/php/verifier.php < "$TASK_DIR/php-input.json" > "$TASK_DIR/php-result.json"
cat "$TASK_DIR/php-result.json"
python - "$TASK_DIR/php-result.json" <<'PY'
import json,sys
result=json.load(open(sys.argv[1]))
assert (result['verdict'],result['state'],result['content']) == ('VALID','COMMITTED','DECRYPTED'), result
print('PASS: creation, check-in, time advancement, release, export and independent PHP verification.')
PY
