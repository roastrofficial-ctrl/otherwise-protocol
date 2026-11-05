<?php
/* Fixture-only producer, independently authored in PHP. Never use these keys. */
require __DIR__.'/../reference/php/verifier.php';
function fixed(string $label,int $n=32): string { return substr(hash('sha256','otherwise-php-fixture-'.$label,true),0,$n); }
function fixtureSeal(string $pk,string $message,string $label): string {
    $sk=fixed('ephemeral-'.$label); $epk=sodium_crypto_box_publickey_from_secretkey($sk);
    $nonce=sodium_crypto_generichash($epk.$pk,'',24);
    return b64($epk.sodium_crypto_box($message,$nonce,sodium_crypto_box_keypair_from_secretkey_and_publickey($sk,$pk)));
}
function signed($b,string $seed): stdClass {
    $kp=sodium_crypto_sign_seed_keypair($seed);
    return obj(['body'=>$b,'signature'=>b64(sodium_crypto_sign_detached("otherwise/solo/1/sign/".$b->kind."\n".canon($b),sodium_crypto_sign_secretkey($kp)))]);
}
$owner=fixed('creator'); $cust=fixed('custodian'); $box=fixed('custodian-box'); $recipient=fixed('recipient'); $dek=fixed('dek');
$creator=b64(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($owner)));
$custodian=b64(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($cust)));
$b=obj(array_merge(hdr('descriptor'),['capsule_id'=>b64(fixed('capsule',16)),'creator_key'=>$creator,'custodian_key'=>$custodian,
    'custodian_box_key'=>b64(sodium_crypto_box_publickey_from_secretkey($box)),'recipient_key'=>b64(sodium_crypto_box_publickey_from_secretkey($recipient)),
    'interval'=>60,'grace'=>10,'nonce'=>b64(fixed('nonce',12))]));
$tag=''; $ct=openssl_encrypt('OTHERWISE SYNTHETIC CAPSULE - laboratory content only.','aes-256-gcm',$dek,OPENSSL_RAW_DATA,ub($b->nonce),$tag,"otherwise/solo/1/content\n".canon($b),16).$tag;
$b->ciphertext_hash=rawhash($ct); $b->ciphertext_size=strlen($ct); $d=signed($b,$owner); $hd=digest($b,'descriptor');
$c=signed(obj(array_merge(hdr('command'),['capsule_id'=>$b->capsule_id,'descriptor_hash'=>$hd,'request_id'=>b64(fixed('request',16)),'action'=>'ARM','basis'=>null,
    'enrollment_box'=>fixtureSeal(ub($b->custodian_box_key),ub($hd).$dek,'enroll')])),$owner);
$e=signed(obj(array_merge(hdr('event'),['capsule_id'=>$b->capsule_id,'descriptor_hash'=>$hd,'seq'=>1,'previous'=>null,'at'=>1000,'clock'=>'trusted','action'=>'ARM','command'=>$c,'release_box'=>null])),$cust);
$release=signed(obj(array_merge(hdr('event'),['capsule_id'=>$b->capsule_id,'descriptor_hash'=>$hd,'seq'=>2,'previous'=>digest($e,'event'),'at'=>1071,'clock'=>'trusted','action'=>'RELEASE','command'=>null,
    'release_box'=>fixtureSeal(ub($b->recipient_key),ub($hd).$dek,'release')])),$cust);
$a=obj(array_merge(hdr('archive'),['descriptor'=>$d,'ciphertext'=>b64($ct),'events'=>[$e,$release]]));
echo json_encode(['input'=>b64(canon($a)),'pins'=>array_intersect_key(get_object_vars($b),array_flip(KEYS)),'options'=>['recipient'=>b64($recipient)]],JSON_UNESCAPED_SLASHES)."\n";
