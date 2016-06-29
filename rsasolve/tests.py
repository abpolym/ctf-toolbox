from sage.all import *
from rsasolve import *
def num2str(t):
	abc = ' ABCDEFGHIJKLMNOPQRSTUVWXYZ'
	t = str(t)
	if len(str(t)) % 2 != 0:
		t="0"+t
	t = [ t[x:x+2] for x in range(0,len(t),2) ]
	msg = ''
	for i in t:
		msg = abc[int(i)] + msg
	return msg[::-1]

def to_bytes(n, length, endianess='big'):
	h = '%x' % n
	s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
	return s if endianess == 'big' else s[::-1]

def test_hastad(ns=None, cs=None, e=3):
	if ns is None:
		n1 = Integer(7491582040538385889995815797321346439940450587934875150712342582430830764458104846320458773919295082983048670720305719186225896583315761678521494414890663)
		n2 = Integer(9479875490840862718231631513496323198616194522063786225389140049343933178476531161203291298588863399662330069956528157456595502346274491156762997111053521)
		n3 = Integer(8164325721942454586836073334368257316581222896046781995902638211629171859223785556955481352709381893629992696921405016915710608371216062602842326820497881)
		ns = [n1, n2, n3]

	if cs is None:
		c1 = Integer(2563368437843099381625160134301055613950695041944920085416524921636908421389680988177593616411293164722220163123128556159222112003805999496527618562373334)
		c2 = Integer(7363698090080958720590455399012227924686199753755178786643696977283077581813973634810727698700121468091873454038106294163350288503686889535932805525947480)
		c3 = Integer(6890000523592029734474849464437363182886004678978272722211783966377675682573890351078188070593865221142715212823857998967938915312980164977258307555639051)
		cs = [c1, c2, c3]

	print hastad_broadcast(ns, cs, e)

def test_fermat(n=None):
	if n is None: n = Integer(12183796266098341405078669034225513226274157726758232242454762825695400178820481404900496616799372025195631319935254275873191629)
	print little_fermat(n)

def test_common_modulus(n=None, cs=None, es=None):
	if n is None or cs is None or es is None:
		n = 0xa5f7f8aaa82921f70aad9ece4eb77b62112f51ac2be75910b3137a28d22d7ef3be3d734dabb9d853221f1a17b1afb956a50236a7e858569cdfec3edf350e1f88ad13c1efdd1e98b151ce2a207e5d8b6ab31c2b66e6114b1d5384c5fa0aad92cc079965d4127339847477877d0a057335e2a761562d2d56f1bebb21374b729743L
		es = []
		cs = []
		es.append(0x1614984a0df)
		cs.append(0x7ded5789929000e4d7799f910fdbe615824d04b055336de784e88ba2d119f0c708c3b21e9d551c15967eb00074b7f788d3068702b2209e4a3417c0ca09a0a2da4378aa0b16d20f2611c4658e090e7080c67dda287e7a91d8986f4f352625dceb135a84a4a7554e6b5bd95050876e0dca96dc21860df84e53962d7068cebd248dL)
		es.append(0x15ef25e10f54a3)
		cs.append(0x7c5b756b500801e3ad68bd4f2d4e1a3ff94d049774bc9c37a05d4c18d212c5b223545444e7015a7600ecff9a75488ed7e609c3e931d4b2683b5954a5dc3fc2de9ae3392de4d86d77ee4920fffb13ad59a1e08fd25262a700eb26b3f930cbdc80513df3b7af62ce22ab41d2546b3ac82e7344fedf8a25abfb2cbc717bea46c47eL)
		es.append(0x1da0ca25f5a8d)
		cs.append(0x65af8559c93c05efecb6a3029dce7e831787878d5539f7b20fc7645ef4892cee23f53384377180a8789e2b2697b7f07fe1e02f3c6b4bb583a072cf27867f558bd51bdc4880b522e2e81c6572b5629241a601acda31356a4fc7767f6a54163f6d16a0bfb6f577c6662e6e1dee78dc6dc51b4d719a1de3d9c2cb5c41a6987cf2b2L)
		es.append(0xc2eac4c2b)
		cs.append(0x711892a29a738e3ac3b996427e4188f23d1c63d9d9c962bfd65b675698e432f27f0ce4e42101576dacaf7b8c78851d406a2695142103d39fbbdd0c111a8587af65834546a5efa8ab6d622a7408d485fe910aaa3ce44168508ab03ad69b15855913c31406be650a492aad1ddde05ac6e655fd842be659ceed886ec6cae8476f1dL)
		es.append(0x1a6c23)
		cs.append(0x57ab8d4c79a58718c0db0dd62a8ba97883e03cd7d14cc3366108a37e8998fc55abd555ca54f81fc975c64e1374d253d95cd957bbb26780e09ca411e8c29742de3414e7cf3f572aea0c35c99b733533e3d39efd5c6c2ce28e67831fb7ecb59186ee791670ffaa08eb6f44614553ec89f7cd5fded09c7c14603e5234f63deb3cf9L)
		es.append(0x2beccafd)
		cs.append(0x6630d2faf104547351da66f760fde920203a041b82f07c0db9034148f9dd17c1f14c2c8ec95ae64e8d0b546f58b998c0412046d48d6057758df3ca300d75106d1ad3210bfce28cd17eebb0fe453d954809aff7ff0fa3044adc6162cfd295cc1d28789e718489c70658758818e5150c09c8fd242d8d5b3699970b042e773b6f7aL)
		es.append(0x280554063943)
		cs.append(0x5bcc5f5435fd087c9615bf04864a82a8fed19576fd311cfde565ca340303cd72d3842ad7a8de9c7123cacbcb9b8be1af01590ef19ff0ebf71e5fec2314639c0d5626cd9ee74fbc8a21325778ba3ef3e1ea310e51b029b5ff9b162b881a240ef4f285dc3a40f62e8a1267e9d6fb3d425509dedefc05ab38f4db5b3f47ddc7619bL)
		es.append(0x23b0d)
		cs.append(0x48bd06fba0691da8883286c21cd49e02eb65d0e3b6ee12b2113940cc64d9f6b921fcb6a8aa82aac592e6a9552d9e27d80e5061501892ec1227ab24dca4236474502156dce8f852eebcbe515c79d998037f55b00858bd16c4ea6fb7b4bea193f6893be766f234b1aa0a38eebaefc2a11264493ea11fb2c103a7552968d8f808bcL)
		es.append(0x6b8a5ae7)
		cs.append(0x6fdcbfb5cd2cacd032ef7200fd49b9f304a6dbd8399f4a91a72d1d9150f97b3b513f44dfc56f6f7c8ec41a8ef9b93a80230a1e65e29d2ef519bb83931d4b0c7a589059cfdf2d571660ab790a9c7e085e3018bf19748abd6d521952b68bc9594c1ad34726658bd9bd445d3b6381ceee57328838e8a129867e505be0ca0d1a1da5L)
		es.append(0x360f1c91fed)
		cs.append(0xa149bb3969479d5b9eff15099ce863d36899d1146c731a91db91ef15869358df4dbe82eaca128d5cd977eeafcb306f949603e5261e9262820f890f8b5dd145718d7af46590eb6474883fe38f399a724d027e04b015d76fd98376d1c5a6d2f63cbc95f15d523692180ca505b327255a67294e5eb69157b3c1230818ac116e48eeL)
		es.append(0xefe30ec7dabb)
		cs.append(0x6fce7de911abe59864e01b9b306c167bdde17da28dfcfb7b3c768ec47d0ae4160cebedae9e482468c65c412eab54ed5d422c3b7b7f818fb6813412b0c1d710f02c763a3cbe4a24140f7a48f543190bfc61a838344ce13e093728a285ec9671c93230aa6abb5f52b83e3f065c9fef894c6c2cb17176e8c2c5cb09f03300de66abL)
		es.append(0x753fdb5)
		cs.append(0xa2403b99c19c2a882bbca51ee414486e1d60db003d16fdf8f30290bae586aaa5500c74b6e8dfe7a3081092da567fd38c57fa04e8a49a94daf229ede6e27fe2571420025aafe123e95b3bcf00a7b64a5e5f48528c8788303c148a4558ab4104b58b2846fde31466f2540b9c5926ffeebfd540ab8da05f9a82db791d72806b74ffL)
		es.append(0x12546aff963f4b6b35fL)
		cs.append(0x7293cec4d46c8073ce78b4ec8d97c086124376cf75fbcc4c0a57159b02e9c7a8545d4fa73f89b0f05d99371b56a565f3b08c8c9725f4f07a513e21c26c4e2a60984ace3f38dab7d84b1208a1a80147377f2552ab040fae4d151939f094543276a823674659dc8de329e47765a8ece154bc9a1aaacee2c7de58876b706690c0cfL)
		es.append(0x11d2843e693)
		cs.append(0x9d96bc542c7afe105b6415d7f0f6d55114d81761f46bfaebbfbf36188f9fbc3759c4693645f4605d17611b9324386333ab0d44505737a8b9a9e73a71fb698f1d0a57fa1e99b18aae8f728a6cee9d774df4ebb5835c9b844ee77817ca04dab9f3cd0ff085c5001100d5e08df98bd1eb6597fb5c1ddf6afd787b2d5274fa03eb7fL)
		es.append(0x9d540226f)
		cs.append(0x4c17528a0d1e36030f882d9c1060ccf974e48178cb7c4c8630968846ca668773881e41a780ba686315ccc487bd12c4389271c51a2c63306b78a2b2f8d8d7736f3ac35d65c9702a5f45d064aa1c7b43cbf2a0723becd8694c325f75d3ef8bf8703690da625c2b139e816bc070f9126067912317d0a3c59e24b87ed611e285e5deL)
		es.append(0xee4c39df4ed4c0f)
		cs.append(0x9fdf693d41e020a9eff786f87f12dc2e2b518ecaa178c8991d06a3ef2e8e136aba94441bc8dbd5be69b05621b635f244afc0f8f5114b7e4c9ace80bb53163acf67bfd4af4ffc5b5bb727c3a0abf794a6494a425ff0e4c08d967dd3ab0e58f4b573d539c5a55a2cecd3d043f23faf2554b6c11c8e25f90084ac0474ee70b70c3bL)
		es.append(0x213901ef4052b8b251c3L)
		cs.append(0xefa14d35d75b629673e8d983f1253134e4584ef16fd13618b23ea4e281f775942d370b384cf2888fb92b3e2f83d1a21448d16676efc9b824afb8992c6fa98530ba28d01fb81fe060ee67f065018562ea513f4da00e00e8a5b3efa966825577960318790f1f76f97f6fd72dde80d0a649687e3237efda595c50da1cf105c1138L)
		es.append(0xe93f)
		cs.append(0x2e1622191a5d6092ef23dabb82bdbf0f5f9eb018f27184c05512679a38be06fc23ca57c1bd4129720e5d562ffebdb30034c655aaea0b78fb996a7264b665488c8c703f1f0169a37688497ab715a4c6bbc5db5839e6800d5f79129c3f2155ad6a07edbaf8f2dfe524c68a41cf7456bf87e2367ded2a8387a6fdc812589375f25cL)
		es.append(0x4042c3955)
		cs.append(0x8caeaa7d272f9606fee9222efd1d922143db738b95bd64746b27bc4c0fd979a2c57b4735131a4391a81bf5f0c0c8eea41d4f91bed4d17784b1956fd89882b97c98009051ac3a03964499c864524d3ddc10299c0290e91707b62ce89b118afe558151be39d61de0483def52c6cb546132ecab85143715bc593a2892b1e41b37b9L)
		es.append(0x61553816b407935)
		cs.append(0x9eade5cb88d453b00c0558f76ab78dc76537588ed1212ffdfdc4ecff98c55457a4b581d157901131c32936d09b6a18238ab243bc40c90af4c73741cd2fc122b8803680b2609eba6af1215a94017ad6d2840203532e3268b7b7dc50c541c281069f1c4b243bff83520481adb5e2b3386bd14c91df1a4b70d2a6b2c725e3e880f2L)
		msg = common_modulus(n, cs, es)

		print to_bytes(msg, 16)
	else:
		print common_modulus(n, cs, es)

def test_wiener(n=None, e=None):
	if n is None:
		n = 27793442438916324852073769571629621363906987250713032009311166214648011023373939003498964284409199884480713385135986361176533064259836096157182701512761162774438591460344749730363750896751142105463370465973545686203136869058209681622767717558658348368914922970584283955915965076793780454197437867142839078375951616760128785617214258715421034891052422779526875326224153609039330478743064168586480200293177807728625471068415603009175557847055007790225381782325646905958312192723314367113063490919001863449037147248487314574466503923962127426615442672910168649857972994900535998275805240520762746701139241437719196227387
		e = 10873793345355951700226688052530453374808239853947122559096444993754553541938268823646797919055213231364346520866549672003735304425878128490248278346244579517255733450345161542782697479000702295092498570993504367459914811037013384682101854080366444844048201061376516723163100028779272502520534391519593286398692160767459902664099175920059385512173404611914135947868359221398976900693313641541897110787540729105956459787357178045524666292969485236381041040678016962140121797060220956647849600187797008925896785087105764155543360404627681208974303988154271866449363502686788753489539697534159340197069564336021637539089
		b = 23281520233097520908335529988490658280934875235569104994074749435513327822145433295270756284047876326361611383814255079127254538969003618584139834598484270015591254165817264518821569763463780577904923871002440961379945665471515217117610692330323613171130204455633138580202533518685289112199872549701216290007713715728679003582650972715492404680401333966952093904011878621266974027369294015835277497938736854229817791684701715101980926348442374797947560907255001378892319904632968749015951893830308215130775597806120193835162275336588498734856320541623005887943603380729120666590170016317226339272993887180377344472105

		p,q,d = wiener_attack(n,e)
		assert p*q==n
		t = pow(b,d,n)
		print num2str(t)

#test_hastad()
#test_fermat()
#test_common_modulus()
#test_wiener()
#test_fermat(n=Integer(10243189921255363578958702669327317711144173434989191540873992161251123635826218828997305156865278990013053915626354016579656085077846515168174544041859115547902528567131096788107114462543800336264133))
print perfect_square(Integer(6497))

sys.exit(1)
"""
c = 0x9dc3d52cd8a5ac46498e9d22c1475afabe1ad9f19f33ee213b0cdbcb8f63e954675d2e7c23f4a4276fd9d5c48d2056ea036dbd80f37ae36917db15f479f6840e303a22106f234a78fa51d3c6619898f7cdf4a0ce3171d7a5fbb9bbb1416ed1b3d5c46d
n = 0x01655d2ce0563f7604e438536ea8bd18717a8d41ba44b36007fc71bfeedf8ddaa6168bcc52f6106c8206c1293f75602875ab8e2310539e163bf86515298d1af2d5f1df9315ee86ea813d713ad6325886cbadb05fa15286d36311af3a2797a0b02b5bf79b
[p, q] = bruteforce_fermat(n)
t = (p-1)*(q-1)

e = 1
while 1:
	if gcd(e, t) != 1:
		e+=1
		continue
	d = findd(e,t)
	m = decrypt(c, n, d)
	e+=1
	#print m
	print to_bytes(m,16)"""
