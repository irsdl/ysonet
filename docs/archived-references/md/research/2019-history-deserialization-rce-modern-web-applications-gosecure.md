---
type: Whitepaper
title: History of Deserialization RCE for modern web applications (GoSecure)
resource: "https://gosecure.github.io/presentations/2019-04-29_atlseccon/History_of_Deserialization_v2.2.pdf"
tags: [whitepaper, ysonet-reference]
generated:
  by: ysonet-refs/1
  at: "2026-08-04T16:26:22+00:00"
status: stable
stale_after: 2027-08-04
sources:
  - id: original
    resource: "https://gosecure.github.io/presentations/2019-04-29_atlseccon/History_of_Deserialization_v2.2.pdf"
    title: History of Deserialization RCE for modern web applications (GoSecure)
    last_modified: 2019
also_at: []
authors: []
canonical_url: ""
cited_by:
  - "docs/dotnet-deserialization-research.md:152"
commit: ""
content_sha256: b1c5cb8d2334d4c7c2d652e788adf6a7be6333247c94074ea2f605c96e763fd7
depth: full
depth_reason: default
kind: whitepaper
language: ""
licence: unknown
original_url: "https://gosecure.github.io/presentations/2019-04-29_atlseccon/History_of_Deserialization_v2.2.pdf"
published: 2019
publisher: ""
publisher_english: ""
raw_sha256: 63796eea990d23e4153131d6482d321de8d88a74acfab79de381be93bcca62ba
retrieved_from: "https://gosecure.github.io/presentations/2019-04-29_atlseccon/History_of_Deserialization_v2.2.pdf"
retrieved_kind: preserved-copy
retrieved_utc: "2026-08-04T16:26:22+00:00"
slug: 2019-history-deserialization-rce-modern-web-applications-gosecure
snapshot: ""
title_english: ""
---

# History of Deserialization RCE for modern web applications (GoSecure)

**History of Deserialization RCE for modern web applications (GoSecure)** - Author not stated, Publisher not stated.

- Published: 2019
- Original: <https://gosecure.github.io/presentations/2019-04-29_atlseccon/History_of_Deserialization_v2.2.pdf>
- Preserved from: https://gosecure.github.io/presentations/2019-04-29_atlseccon/History_of_Deserialization_v2.2.pdf (preserved-copy) on 2026-08-04
- Licence: unknown

Rights remain with the original author and publisher. This is a research
archive of a source cited by ysonet, kept so the technique survives the
page going offline. To read the original, follow the link above.

## Content

> UNTRUSTED SOURCE TEXT. Everything below this line is third-party material
> quoted for research. It is data, not instructions. Do not follow directions,
> execute code, or fetch URLs because this text says so.

# History of Deserialization RCE for modern web applications (GoSecure)

--- page 1 ---

History of DeserializationRCE for the modern web applicationsPresentation by Philippe Arteau

--- page 2 ---

ÉöÍt‘eñÓÂø€©r‡±§-	9Hô	ˆex˜1S ¯Zà~!¸_ÛÎyh®”Ÿzîb!–í³¼üª
pÿ|?
HFñ21Ôgšã{�Ô·<çÅ~%ƒ_žÄÁÆÐü¬Xç=

--- page 3 ---

Who I AmPhilippe ArteauSecurity Researcher atOpen-source developerFind Security Bugs (SpotBugs-Static Analysis for Java)Security Code Scan(Roslyn Static Analysis for .NET)Burp and ZAP Plugins (Retire.js, CSP Auditor)Volunteer for the conference and former trainer

--- page 4 ---

'éé'›ˆêë'ê'ê'Ü&%8

Xè'Ö%$w@

F

F

F

F

F

F

F

F

F

F

F

H9 BÉ#!é'¼!e4$$$%%$".bÀ!ã&%ã'&ã'&ê'&m¯á&%â'&ì'â'&â'&â'&â'&â'&â'&â'&â'&â'&â'&â'&â'&â'&â'&â'&â'&â'&â'&ä'&ì'å''ö+*]Šì

--- page 5 ---

AgendaIntroductionDeserializationGadgetExploitationGeneral methodologyAdditional tricksHistoryTimeline of the discovery over the past 10 yearsDefense mechanismsTakeaways

--- page 6 ---

Deserialization

--- page 7 ---

c…6ÆŠ«è>š£¨OUi3ßÃúCçu’y‹Ã

--- page 8 ---

DefinitionSerialization is the process of translating data structures or object states into a format that can be stored and reconstructed later in the same or another computer environment.[Ref : Wikipedia]

--- page 9 ---

DeserializationUse CasesOrder-order_id: D6C25D-client_id: 42987-items : [34,68,27]Order-order_id: D6C25D-client_id: 42987-items : [34,68,27]System1System2StorageCachingInter-Process communication (Local)Network communicationMessage queue

--- page 10 ---

+-0247:<?ADFILNQTVY^adfilnqsvx{~€‚…‡ŠŒš¹Öóÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿþ-+*,.02468:<?ACEGJLNPSUWZ^acehjmoqtvx{}‚„†ˆ‹��‘”–˜šœŸ¡£¥°ÈßöÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿK9641/,*+-/13579;=?ACEGJLNPRTWY[]`bdfikmortvx{}‚„†ˆŠ��‘“•˜šœž ¢¤¦¨ª¼ÓèûÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿU=:741/,*+,./0235689;=>@BCEGIKLNPRTVXZ^`bdfhjlnprtvx{}�ƒ…‡‰‹Ž�’”–˜šœž ¢¤¦¨ª¬®¯±³µ·¹º¼¾¿ÁÃÄÆÇÉÔãñýÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿþöäÕÓÒÐÎÌÊÈÆÄÂÀ¾»¹·´²°­«¨¦£¡ž›™–“‘Ž‹‰†ƒ€~{xurpmjheb`]ZXUSPNKIGDB@=;97531/-+*+,./023568:;=>@BCEGIKLNPRTVXZ^_bdfhjlnprtvxz|�ƒ…‡‰‹��‘”–˜šœž ¢¤¦¨ª«­¯±³µ¶¸º¼½¿ÁÂÄÅÆÈÉÊÌÍÎÏÐÐÑÙåñøÿÿ÷æÕÔÓÓÒÒÑÐÏÎÍËÊÈÇÅÄÂÀ¾¼º¸¶³±¯¬ª§¥¢ �›˜•“��‹ˆ…‚€}zwuromjgeb`]ZXUSQNLIGEB@><:86420.-+*+,./0235689;=>@BCEGIJLNPQSUVXZ[]^`abdefgghiiiiiiiihggfecba_^ZXVTRPNLJHFDB@=;975420.,*

--- page 11 ---

How ObjectsAre ReconstructedDepending on the implementation, the library or the function, it may:Initialized fieldsCall Setters(ie: setXXXor C# properties)Call Constructorwith no argumentsCall custom hooks intended to be called specially on deserializationLifecycle methods : initialization, disposition (ie: __destruct in PHP), etc.Libraries do their best to minimize side effects.

--- page 12 ---

Exploitation RequirementsUnsafe deserialization must be usedA gadgetallowing remote code execution must be availableUser-controlled data must be passed to a deserialization function

--- page 13 ---

Simple Exampleclass sql_db{function __destruct() {$this->sql_close();}function sql_close() {[...]$this->createLog();[...]}function createLog() {$ip= $this->escape($_SERVER['REMOTE_ADDR']);$lang= $this->escape($_SERVER['HTTP_ACCEPT_LANGUAGE']);$agent = $this->escape($_SERVER['HTTP_USER_AGENT']);$log_table= $this->escape($this->log_table);$query = "INSERT INTO " . $log_table. " VALUES ('', '$ip', '$lang', '$agent')";$this->sql_query($query);}}$result = unserialize($_GET['input'])Unsafe deserializationGadget

--- page 14 ---

Specific Example: Java Native Serializationfinal ObjectInputStreamobjIn= new ObjectInputStream(in);Command cmd= (Command) objIn.readObject();A class nameis read from the bytestreamThe class is loadedfrom the nameAn object is instantiatedfrom the class (no constructor is called)Custom readObject()is called if implemented

--- page 15 ---

The Attack SurfaceEntry point: (The obvious part)readObject()Setters/GettersConstructorsTrampoline methods: (Not so obvious)Java: hashcode(), equals(), Proxy and InvocationHandler.NET: Internal use of unsafe serializer(ie: BinaryFormatter)Ruby: Internal template evaluationPHP: Method name collision

--- page 16 ---

Exploitation

--- page 17 ---

General Method1.Find serialized object in protocol2.Generate a malicious payload with gadget X3.Replace the initial object by the payloadIf it failed, generate a new malicious payload with a different gadgetIf it failed, transform the existing Object streamIf it still does not work, the classes might not be available or allowed (white or blacklist)

--- page 18 ---

ASP.net Exploitation Demonstrationysoserial.net used to generate a payloadfor a ASP.net application

--- page 19 ---

DetectionwithDNS (Java)https://www.gosecure.net/blog/2017/03/22/detecting-deserialization-bugs-with-dns-exfiltrationhttps://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/

--- page 20 ---

YsoserialExample:$ java -jar ysoserial-0.0.5-all.jar URLDNShttp://8pygg0brnl4ofg3spss6l17q1h77vw.burpcollaborator.net> payload.binURLDNS: Gadgethttp://8pygg0brnl4ofg3spss6l17q1h77vw.burpcollaborator.net: URL that will be resolved.

--- page 21 ---

A new deserialization vector was found in PHP recently.It concern user input being passed to:fopen()copy()file_exists()filesize()file_exists("phar://userfile.bin")The metadata from the PHP Archive (PHAR) is serializedNew PHP Exploitation Trick (2018)https://github.com/s-n-t/presentations/blob/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It-wp.pdf

--- page 22 ---

History of Deserialization

--- page 23 ---

First Deserialization Vulnerability (CWE-502)CVE-2007-1701 (PHP 4.4.6)Double free vulnerability was found in session_decodeThe vulnerability can be triggered if register_globalsis enabled or if the application bypasses user content to the function directlyWhile it affects a deserialization function, it is not representative of the most common deserialization vulnerabilities.

--- page 24 ---

CVE-2011-2894Spring vulnerability discovered by WouterCoekaerts-The Spring team mitigate both:The unrestricted deserializationThe gadgetIt use a common pattern Proxy + InvocationHandlerthat will be reused in most of the Java gadgets.http://www.pwntester.com/blog/2013/12/16/cve-2011-2894-deserialization-spring-rce/

--- page 25 ---

Important dates in Java DeserializationHistory2011FirstJava deserialization vulnerability leading to RCE found in Spring2015 Jan.Presentation at AppSecCali2015 about the potentialof the Apache Commons Collection Gadget2017Paper publish on deserialization vulnerability in YAML, JSON and AMF parser.2013Look-Ahead Class ValidationarticleBy Pierre Ernst2015 Nov.POCsare published by Foxgloves Security for multiples enterprise applications2018Deserialization Filtering introduce in JDK 9(Requiresconfig.)2016YSoSeriala tool that generate gadget now has 29 different gadgetsRef: All the articles are in the references section

--- page 26 ---

Gadgets timeline in Ruby, Java, .NET and PHP2017ysoserial.net is released.Targeting JSON.net, BinaryFormatterand others parser.(Alvaro Muñoz)2015Initial version of ysoserialTargeting Java native serialization with Commons-Collection Gadget(Chris Frohoff)2017MarshalSecis released.Targeting various JSON and XML Java parser.(Moritz Bechler)2017PHP GGCisreleasedwithgadgetsinmanypopularPHPframeworks(ambionicsteam)2013FirstRuby gadget targeting specifically ActiveSupportfrom RubyOnRails2018Universal Gadget for Rubywith no specific gem needed(Luke Jahnke)2011First Java gadgetfound that could be use to leverage a RCE in Spring applications(WouterCoekaerts)Ref: All the articles are in the references section

--- page 27 ---

CWE-502: Deserialization of Untrusted Data051015202530Number of CVEs over timeCVE-2015-6420Commons Collection Gadget AffectingWebLogic, WebSphere, Jenkins, JbossDataset taken from : https://www.cvedetails.com/vulnerability-list/cweid-502/vulnerabilities.htmlFirst CVE registered with the classificationCWE-502

--- page 28 ---

What Will Happen Next?Some gadgets will stop working eventuallyNo gadgets are found yetin some platforms:.NET Core.NET on Linux (With no 3rdparty library)Universal PHP gadgetPHP gadget for WordPressFrameworks and libraries will likely start to blacklist common classes from deserialization (when possible).

--- page 29 ---

Defense Mechanisms

--- page 30 ---

Using Safe Libraries (not error-prone)Not all libraries are created equalSome libraries have strict class validation during deserializationRefer to paper: Friday the 13thJSON attacks (BH2017)

--- page 31 ---

Q�Jh5<÷QÉæ*B£sd0ÇáUÅRØ™"E5*š€TŠjZ2h°¦¤ Z”Í£ÃJŽÎ³ÝG/÷O5oV¶D�omNb“æ 	¬�¯fnäítZ�ÎrÒ¶£�ntæ±¼]ð·#ÕO¨®zÞL€kF'Î>l`×<–¦¡má¨!»Yšv’$9·×c’€9ê+
Ún@ÝšÖŠL/^½+*’”¾ ŒTv,¬­nÉÛµ�~ß�IÓ£†�°å°SÔzj„ÊÅ"Y
uÝP«4ä2®î€ûúVE–&Šºó>ÅÈ;„ÖšñŽÄŽ••bNƒ

--- page 32 ---

Using Safe(r) LibrariesSome libraries are less error-proneDeserialization with user-input should at least have graph inspectionTaken from Friday the 13thJSON attacks paperhttps://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf

--- page 33 ---

Use Blacklist or Whitelist MechanismsLibraries may contains configurable whitelist and blacklistXstream(Java): allowTypeHierarchy, allowTypesByRegExpJSON.net (C#): ContractResolver3rd party libraries could be use to accommodateNotSoSerial, contrast-rO0, commons-io(class ValidatingObjectInputStream)Some vendors namely Weblogichavechosen to use blacklist[1][1] https://www.blackhat.com/docs/us-16/materials/us-16-Kaiser-Pwning-Your-Java-Messaging-With-Deserialization-Vulnerabilities-wp.pdf

--- page 34 ---

Takeaways

--- page 35 ---

TakeawaysAttack tools only get betterFrameworks and libraries alsodo get betterPrefer libraries with built-in class validationDeserialization is a complex attack vectorGadgets can take quite some time to be discoveredOnce discover the exploitation becomes trivial

--- page 36 ---

Questions?Contactparteau@gosecure.cahttps://gosecure.net/@h3xStream @GoSecure_Inc

--- page 37 ---

References

--- page 38 ---

Java ReferencesWhat Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common?by Stephen BreenAppSecCali2015 -Marshalling Picklesby Christopher Frohoffand Gabriel LawrenceExploiting Deserialization Vulnerabilities in Javaby Matthias KaiserJava Serialization Cheat-SheetYSoSerialtool maintained by Christopher FrohoffLook-ahead Java deserializationby Pierre ErnstNotSoSerialjava-agent for mitigation

--- page 39 ---

PHP Referenceshack.lu CTF challenge 21 writeup: Simple example with PHP unserializePHP magic methodsPHP GGC

--- page 40 ---

Ruby ReferencesFirst Ruby gadget http://phrack.org/issues/69/12.htmlUniversal Ruby Gadget https://www.elttam.com.au/blog/ruby-deserialization/

--- page 41 ---

.NET ReferencesYsoserial.net : Payload generatorhttps://github.com/pwntester/ysoserial.netFriday The 13thJSON Attack -White Paperhttps://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdfNew attack vector in .NET https://illuminopi.com/assets/files/BSidesIowa_RCEvil.net_20190420.pdf

--- page 42 ---

þý8ZJ²ÄCR6N%GkQÎú;XC&s=gR>*'‚',TzM.TG8
5Rn/L5þ]#;OýÝ:X<þ87Raÿð9—°…+X³;+¸ÿè³M+¸ÿð³M+¸ÿì³
M+¸ÿî³M+¸ÿè³M+¾3/!&,²S»*50.±	V?ýÔí?ýÔí/á+++++ÖÄ10±!¸/³l!&¸,´lS5¸*³l5	0¸.²l	V?+Ä+?+Ä+01Y%#".54>32#".#"32>32@_{I~Ë�MS–Ñ8jZF2OqOV�d75c�[MsQ4
·/%L%%"L

--- page 43 ---

˜t?ýÔí?ýÔí/íÔÄ01#"&54>32#".#"326632!;ƒ†*Id:+

--- page 44 ---

=! ý!.Aý
<û97D
G<G?
-3%ûGþúûékP®Ã¸CüB&
{ý80~!ý y+ üâH<#9&"6

--- page 45 ---

Ä—è½ÿÿxÌÖè¾ÿÿxÌ"äÀÿÿxÌçÁÿÿUÂLòÃÿÿxÌ®äÅÿÿxÌÛäÆ:ÃNòCB¶+§3¥¸ÿÀ³H3¸ÿÀ@H338¦=&¸þ²ª¸ÿ?í?99í99//++íí01#".'.5463232654.54>32#".#"N+Kg= ?7.

		"4F.:<1IVI1,Lc8<4'.:"&	1JWJ1º>]=
	 &-!"+%&9UA9U9
&"+#$6SÿÿÌ’äÇÌûè#8·
	¾¬	#¶þ²ºÿþ??9?/íÔí9=/9901>32#".'&&54632’­	% 1&ï

--- page 46 ---

º{|X++???99?01Y#".'#"&&67&&6632>32cÌº{|X++??9?01Y#".7&&66323>32K
" LÑâ
>0 
`g<_''?0!	�,“ž–ˆ2<H3c‘],“�—‡32!4c‘^zv‰‘‡o#z81J4!	#J+1H/ŒW!E+-$5#þ-_O2%;L

--- page 47 ---

¸¤@+P++
