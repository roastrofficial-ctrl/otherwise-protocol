<?php
/* Independent Solo parser, canonicalizer and lifecycle verifier. No Python calls. */
declare(strict_types=1);
const PROFILE='otherwise.solo.v1';
const SUITE='ed25519-sha256-aes256gcm-sodiumseal-v1';
const MAXINT=9007199254740991;
const H=['profile','v','suite','kind'];
class ProtocolFault extends Exception {}
function need($condition,string $code='SCHEMA'): void { if (!$condition) throw new ProtocolFault($code); }
function hdr(string $kind): array { return ['profile'=>PROFILE,'v'=>1,'suite'=>SUITE,'kind'=>$kind]; }
function canon($x,int $depth=1): string {
    need($depth<=16,'LIMIT');
    if ($x===null) return 'null';
    if (is_bool($x)) return $x?'true':'false';
    if (is_int($x)) { need($x>=0 && $x<=MAXINT,'RANGE'); return (string)$x; }
    if (is_string($x)) { need(!preg_match('/[^\x20-\x7e]/',$x)); return json_encode($x,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR); }
    if (is_array($x)) return '['.implode(',',array_map(fn($v)=>canon($v,$depth+1),$x)).']';
    need($x instanceof stdClass); $a=get_object_vars($x); ksort($a,SORT_STRING); $out=[];
    foreach ($a as $k=>$v) $out[]=canon((string)$k,$depth+1).':'.canon($v,$depth+1);
    return '{'.implode(',',$out).'}';
}
function obj(array $a): stdClass { return (object)$a; }
class Parser {
    private int $i=0; private int $n;
    function __construct(private string $s) { $this->n=strlen($s); need($this->n<=33554432,'LIMIT'); }
    private function ws(): void { while ($this->i<$this->n && str_contains(" \r\n\t",$this->s[$this->i])) $this->i++; }
    private function str(): string {
        $start=$this->i++; $escape=false; $done=false;
        while ($this->i<$this->n) {
            $c=$this->s[$this->i++];
            if ($escape) $escape=false;
            elseif ($c==='\\') $escape=true;
            elseif ($c==='"') { $done=true; break; }
        }
        need($done,'MALFORMED');
        try { $x=json_decode(substr($this->s,$start,$this->i-$start),false,16,JSON_THROW_ON_ERROR); }
        catch (JsonException $e) { throw new ProtocolFault($e->getCode()===JSON_ERROR_UTF16?'SCHEMA':'MALFORMED'); }
        need(is_string($x),'MALFORMED'); return $x;
    }
    private function val(int $depth=1) {
        need($depth<=16,'LIMIT'); $this->ws(); need($this->i<$this->n,'MALFORMED'); $c=$this->s[$this->i];
        if ($c==='"') return $this->str();
        if ($c==='{' || $c==='[') {
            $object=$c==='{'; $end=$object?'}':']'; $this->i++; $this->ws(); $a=[]; $seen=[];
            if (($this->s[$this->i]??'')===$end) { $this->i++; return $object?obj([]):[]; }
            while (true) {
                $this->ws();
                if ($object) {
                    need(($this->s[$this->i]??'')==='"','MALFORMED'); $key=$this->str();
                    need(!array_key_exists($key,$seen),'MALFORMED'); $seen[$key]=true;
                    $this->ws(); need(($this->s[$this->i++]??'')===':','MALFORMED');
                    $a[$key]=$this->val($depth+1);
                } else $a[]=$this->val($depth+1);
                $this->ws(); $next=$this->s[$this->i++]??'';
                if ($next===$end) break;
                need($next===',','MALFORMED');
            }
            return $object?obj($a):$a;
        }
        foreach (['null'=>null,'true'=>true,'false'=>false] as $literal=>$v) {
            if (substr($this->s,$this->i,strlen($literal))===$literal) { $this->i+=strlen($literal); return $v; }
        }
        foreach(['NaN','Infinity','-Infinity'] as $bad) if(substr($this->s,$this->i,strlen($bad))===$bad) throw new ProtocolFault('NONCANONICAL');
        need((bool)preg_match('/\G-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/A',$this->s,$m,0,$this->i),'MALFORMED');
        $token=$m[0]; $this->i+=strlen($token);
        need((bool)preg_match('/^(?:0|[1-9][0-9]*)$/D',$token),'NONCANONICAL');
        need(strlen($token)<=16 && (strlen($token)<16 || strcmp($token,(string)MAXINT)<=0),'RANGE');
        return (int)$token;
    }
    function parse() {
        $x=$this->val(); $this->ws(); need($this->i===$this->n,'MALFORMED'); need(canon($x)===$this->s,'NONCANONICAL'); return $x;
    }
}
function parse(string $s) { return (new Parser($s))->parse(); }
function b64(string $s): string { return rtrim(strtr(base64_encode($s),'+/','-_'),'='); }
function ub($s,?int $n=null): string {
    need(is_string($s) && (bool)preg_match('/^[A-Za-z0-9_-]*$/D',$s));
    $r=base64_decode(strtr($s,'-_','+/').str_repeat('=',(-strlen($s))&3),true);
    need($r!==false && b64($r)===$s && ($n===null || strlen($r)===$n)); return $r;
}
function digest($x,string $domain): string { return b64(hash('sha256',"otherwise/solo/1/$domain\n".canon($x),true)); }
function rawhash(string $s): string { return b64(hash('sha256',$s,true)); }
function fields($x,array $names): void { need($x instanceof stdClass); $a=array_keys(get_object_vars($x)); sort($a); sort($names); need($a===$names); }
function uint($v,int $lo=0,int $hi=MAXINT): void { need(is_int($v)); need($v>=$lo && $v<=$hi,'RANGE'); }
function head($b,string $kind): void {
    need($b instanceof stdClass);
    foreach(H as $k) need(property_exists($b,$k));
    need($b->profile===PROFILE,'UNSUPPORTED_PROFILE'); need($b->v===1,'UNSUPPORTED_VERSION');
    need($b->suite===SUITE,'UNSUPPORTED_SUITE'); need($b->kind===$kind);
}
function envelope($e): void { fields($e,['body','signature']); ub($e->signature,64); need($e->body instanceof stdClass); }
function scopeShape($b): void { ub($b->capsule_id,16); if(property_exists($b,'descriptor_hash')) ub($b->descriptor_hash,32); }
const KEYS=['creator_key','custodian_key','custodian_box_key','recipient_key'];
function descriptorShape($e): void {
    envelope($e); $b=$e->body; head($b,'descriptor');
    fields($b,array_merge(H,['capsule_id','creator_key','custodian_key','custodian_box_key','recipient_key','interval','grace','nonce','ciphertext_hash','ciphertext_size']));
    scopeShape($b); foreach(KEYS as $k) ub($b->$k,32); ub($b->nonce,12); ub($b->ciphertext_hash,32);
    uint($b->interval,60,31536000); uint($b->grace,1,2592000); uint($b->ciphertext_size,16,1048592);
}
function commandShape($e): void {
    envelope($e); $b=$e->body; head($b,'command'); need(in_array($b->action??null,['ARM','CHECKIN','DISARM'],true));
    fields($b,array_merge(H,['capsule_id','descriptor_hash','request_id','action','basis'],$b->action==='ARM'?['enrollment_box']:[]));
    scopeShape($b); ub($b->request_id,16);
    if($b->action==='CHECKIN') ub($b->basis,32); else need($b->basis===null);
    if($b->action==='ARM') ub($b->enrollment_box,112);
}
function eventShape($e): void {
    envelope($e); $b=$e->body; head($b,'event');
    fields($b,array_merge(H,['capsule_id','descriptor_hash','seq','previous','at','clock','action','command','release_box']));
    scopeShape($b); uint($b->seq,1,10000); uint($b->at); if($b->previous!==null) ub($b->previous,32);
    need(in_array($b->clock,['trusted','held'],true)); need(in_array($b->action,['ARM','CHECKIN','DISARM','RELEASE'],true));
    if($b->action==='RELEASE') { need($b->command===null); ub($b->release_box,112); }
    else { need($b->release_box===null); commandShape($b->command); }
}
function pointValid(string $p): bool {
    static $ffi=null;
    if($ffi===null) $ffi=FFI::cdef('int crypto_core_ed25519_is_valid_point(const char *); int crypto_scalarmult_ed25519_noclamp(char *,const char *,const char *); int crypto_core_ed25519_add(char *,const char *,const char *);','libsodium.so.23');
    if($ffi->crypto_core_ed25519_is_valid_point($p)!==1) return false;
    $lm1=hex2bin('ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010');
    $t=FFI::new('char[32]'); $r=FFI::new('char[32]');
    // Sodium's published main-subgroup workaround for releases <=1.0.20.
    if($ffi->crypto_scalarmult_ed25519_noclamp($t,$lm1,$p)!==0 || $ffi->crypto_core_ed25519_add($r,FFI::string($t,32),$p)!==0) return false;
    return FFI::string($r,32)==="\x01".str_repeat("\0",31);
}
function signature($key,$e): void {
    $pk=ub($key,32); $s=ub($e->signature,64); $l=hex2bin('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010');
    need(pointValid($pk) && pointValid(substr($s,0,32)) && strcmp(strrev(substr($s,32)),strrev($l))<0,'BAD_SIGNATURE');
    need(sodium_crypto_sign_verify_detached($s,"otherwise/solo/1/sign/".$e->body->kind."\n".canon($e->body),$pk),'BAD_SIGNATURE');
}
function scope($b,$d): void { need($b->capsule_id===$d->body->capsule_id && $b->descriptor_hash===digest($d->body,'descriptor'),'SCOPE'); }
function verifyArtifact(string $raw,$pins,$options=null): stdClass {
    $options=$options??obj([]);
    $r=obj(array_merge(hdr('verification'),['descriptor_hash'=>null,'verdict'=>'INVALID','state'=>'UNKNOWN','head'=>null,'authorization'=>null,'content'=>'NOT_ATTEMPTED','freshness'=>'UNKNOWN','code'=>'MALFORMED']));
    try {
        $a=parse($raw); head($a,'archive'); fields($a,array_merge(H,['descriptor','ciphertext','events']));
        $d=$a->descriptor; $ct=ub($a->ciphertext); $events=$a->events;
        if(is_object($d) && is_object($d->body??null)) head($d->body,'descriptor');
        if(is_array($events)) {
            need(count($events)<=10000,'LIMIT');
            foreach($events as $e) if(is_object($e) && is_object($e->body??null)) {
                head($e->body,'event'); $c=$e->body->command??null;
                if(is_object($c) && is_object($c->body??null)) head($c->body,'command');
            }
        }
        descriptorShape($d); $r->descriptor_hash=digest($d->body,'descriptor');
        need(is_array($events) && count($events)<=10000,'LIMIT'); foreach($events as $e) eventShape($e);
        $snap=null;
        if(isset($options->snapshot)) {
            $snap=parse(ub($options->snapshot)); envelope($snap); $sb=$snap->body; head($sb,'snapshot');
            fields($sb,array_merge(H,['capsule_id','descriptor_hash','challenge','head','sampled_at','clock','events']));
            scopeShape($sb); ub($sb->challenge,32); if($sb->head!==null) ub($sb->head,32);
            need(in_array($sb->clock,['trusted','unavailable'],true));
            if($sb->clock==='trusted') uint($sb->sampled_at); else need($sb->sampled_at===null);
        }
        descriptorShape($d); need(is_array($events) && count($events)<=10000,'LIMIT'); foreach($events as $e) eventShape($e);
        need($pins instanceof stdClass,'UNTRUSTED_IDENTITY');
        foreach(KEYS as $k) need(($pins->$k??null)===$d->body->$k,'UNTRUSTED_IDENTITY');
        if(isset($pins->descriptor_hash)) need($pins->descriptor_hash===digest($d->body,'descriptor'),'SCOPE');
        signature($d->body->creator_key,$d);
        foreach($events as $e) { signature($d->body->custodian_key,$e); if($e->body->command!==null) signature($d->body->creator_key,$e->body->command); }
        if($snap!==null) signature($d->body->custodian_key,$snap);
        need(strlen($ct)===$d->body->ciphertext_size && rawhash($ct)===$d->body->ciphertext_hash,'CONTENT_COMMITMENT');
        foreach($events as $e) { scope($e->body,$d); if($e->body->command!==null) scope($e->body->command->body,$d); }
        if($snap!==null) { scope($sb,$d); need(canon($sb->events)===canon($events),'HISTORY_CONFLICT'); }
        $last=null; $lastAt=0;
        foreach($events as $i=>$e) {
            $b=$e->body; if($i===0 && $b->seq>1) throw new ProtocolFault('INCOMPLETE_HISTORY');
            need($b->seq===$i+1 && $b->previous===$last,'HISTORY_ORDER'); need($b->at>=$lastAt,'TIME');
            $last=digest($e,'event'); $lastAt=$b->at;
        }
        foreach(get_object_vars($options->anchors??obj([])) as $seq=>$h) {
            $n=(int)$seq; need($n>=1); ub($h,32);
            if($n>count($events)) throw new ProtocolFault($snap!==null?'HISTORY_CONFLICT':'INCOMPLETE_HISTORY');
            need(digest($events[$n-1],'event')===$h,'HISTORY_CONFLICT');
        }
        $last=null; $lastAt=0; $deadline=null; $terminal=null; $ids=[];
        foreach($events as $i=>$e) {
            $b=$e->body; $action=$b->action; $at=$b->at; $c=$b->command;
            need($terminal===null,'LIFECYCLE'); need($b->clock==='trusted' || ($action==='DISARM' && $at===$lastAt),'TIME');
            if($action!=='RELEASE') {
                need($c->body->action===$action,'LIFECYCLE'); need(!isset($ids[$c->body->request_id]),'HISTORY_ORDER'); $ids[$c->body->request_id]=true;
            }
            need($i===0?$action==='ARM':$action!=='ARM','LIFECYCLE');
            if($action==='CHECKIN') {
                need($i+1<10000,'LIFECYCLE'); need($c->body->basis===$last,'HISTORY_ORDER'); need($at<=$deadline+$d->body->grace,'TIME');
            }
            if($action==='ARM' || $action==='CHECKIN') { $deadline=$at+$d->body->interval; need($deadline+$d->body->grace<=MAXINT,'RANGE'); }
            if($action==='RELEASE') { need($deadline!==null && $at>$deadline+$d->body->grace,'TIME'); $terminal='COMMITTED'; }
            elseif($action==='DISARM') $terminal='DISARMED';
            $last=digest($e,'event'); $lastAt=$at;
        }
        $r->descriptor_hash=digest($d->body,'descriptor'); $at=$options->at??null; $fresh='HISTORICAL';
        if($snap!==null) {
            $elapsed=$options->elapsed??null;
            need($sb->challenge===($options->challenge??null) && (is_int($elapsed)||is_float($elapsed)) && $elapsed>=0 && $elapsed<=10,'TIME');
            need($sb->head===$last,'HISTORY_ORDER'); $at=$sb->sampled_at; $fresh='SAMPLED';
        }
        $status=$terminal??($last===null?'UNARMED':'UNKNOWN');
        if($terminal===null && $last!==null && $at!==null) {
            uint($at); need($at>=$lastAt,'TIME'); $status=$at<=$deadline?'ARMED':($at<=$deadline+$d->body->grace?'GRACE':'ELIGIBLE');
        }
        if($status==='COMMITTED' && isset($options->recipient)) {
            try {
                $sk=ub($options->recipient,32); $pk=sodium_crypto_box_publickey_from_secretkey($sk);
                $keypair=sodium_crypto_box_keypair_from_secretkey_and_publickey($sk,$pk);
                $inside=sodium_crypto_box_seal_open(ub($events[count($events)-1]->body->release_box,112),$keypair);
                need($inside!==false && strlen($inside)===64 && substr($inside,0,32)===ub($r->descriptor_hash),'CONTENT_AUTHENTICATION');
                $core=clone $d->body; unset($core->ciphertext_hash,$core->ciphertext_size);
                $plain=openssl_decrypt(substr($ct,0,-16),'aes-256-gcm',substr($inside,32),OPENSSL_RAW_DATA,ub($d->body->nonce,12),substr($ct,-16),"otherwise/solo/1/content\n".canon($core));
                need($plain!==false,'CONTENT_AUTHENTICATION'); $r->content='DECRYPTED';
            } catch(Throwable $e) { $r->content='FAILED'; throw new ProtocolFault('CONTENT_AUTHENTICATION'); }
        }
        $r->verdict='VALID'; $r->state=$status; $r->head=$last; $r->authorization=$status==='UNKNOWN'?null:$status==='COMMITTED'; $r->freshness=$fresh;
        $r->code=$status==='COMMITTED'?'OK_RELEASE':($status==='DISARMED'?'OK_DISARM':($snap!==null?'OK_SNAPSHOT':'OK_HISTORY'));
    } catch(ProtocolFault $e) {
        $r->code=$e->getMessage(); $r->verdict=str_starts_with($r->code,'UNSUPPORTED_')?'UNSUPPORTED':($r->code==='INCOMPLETE_HISTORY'?'INCOMPLETE':'INVALID');
    } catch(Throwable $e) { $r->code='SCHEMA'; }
    return $r;
}
if(realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__) {
    if(($argv[1]??'')==='--corpus') {
        $cases=json_decode(file_get_contents($argv[2]),false,512,JSON_THROW_ON_ERROR); $fail=[];
        foreach($cases->cases as $case) {
            $actual=verifyArtifact(ub($case->input),$case->pins,$case->options);
            if(canon($actual)!==canon($case->expected)) $fail[]=obj(['name'=>$case->name,'expected'=>$case->expected,'actual'=>$actual]);
        }
        echo json_encode(['cases'=>count($cases->cases),'disagreements'=>count($fail),'failures'=>$fail],JSON_UNESCAPED_SLASHES)."\n";
        exit(count($fail)?1:0);
    }
    $request=json_decode(stream_get_contents(STDIN),false,512,JSON_THROW_ON_ERROR);
    echo canon(verifyArtifact(ub($request->input),$request->pins,$request->options??null))."\n";
}
