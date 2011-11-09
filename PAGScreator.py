#!/usr/bin/python -d
# -*- coding: utf-8 -*-
import ldap, sys, os, string, re, codecs

import ConfigParser
import subprocess
import logging
import xml.dom.minidom
import datetime

# A. Anli ajout de strftime pour le rotate log par mois
today = datetime.date.today().strftime("%Y-%m")

configFile=sys.argv[1]
inXmlFile=sys.argv[2]
outXmlFile=sys.argv[3]
logFileName=sys.argv[4]+str(today)


Config = ConfigParser.ConfigParser()
Config.read(configFile)

def safeConfigGet(section, option):
    if Config.has_option(section, option):
        return Config.get(section, option)
    else:
        return ""

esup_portail  = re.search("esup-portail", Config.get('common', 'type'))
esup_portail3 = re.search("esup-portail3", Config.get('common', 'type'))
typo3         = re.search("typo3", Config.get('common', 'type'))
uaiPrefix     = Config.get('common', 'uaiPrefix')
ldapServer    = Config.get('ldap', 'server')
ldapUsername  = Config.get('ldap', 'username')
ldapPassword  = Config.get('ldap', 'password')
baseDN        = Config.get('ldap', 'baseDN')
etapesDN      = Config.get('ldap', 'etapesDN')
restrictIdp   = safeConfigGet('common', 'restrictIdp')
oldKeys       = True

personnelDescription = {
    'staff': 'personnels administratifs et techniques', 
    'researcher': 'chercheurs', 
    'teacher' : 'enseignants',
    }
personnelTypes = personnelDescription.keys()

attributeStringEqualsIgnoreCaseTester="org.jasig.portal.groups.pags.testers.StringEqualsIgnoreCaseTester"

membersRegexTester={ "placeholder": None }

structuresDN = "ou=structures,"+baseDN

typo3attrs = {
    'eduPersonAffiliation': 'HTTP_SHIB_EP_UNSCOPEDAFFILIATION',
    'supannEtuEtape': 'HTTP_SHIB_SUPANN_SUPANNETUETAPE',
    'supannEntiteAffectation': 'HTTP_SHIB_SUPANN_SUPANNENTITEAFFECTATION',
    'Shib-Identity-Provider': 'Shib-Identity-Provider',
}

timeout=0

class EmptyMembersList(Exception):
    pass

def etudiantsKey():
    if oldKeys:
        return "diploma"
    return "etudiants"

def etudiantsComposanteKey(composante):
    if oldKeys:
        return "diploma_composante_" + composante
    return "etudiants_composante_" + composante

def businessCategoryKey(businessCategory):
    if oldKeys:
        if businessCategory == "pedagogy":
            return "composantes"
        elif businessCategory == "research":
            return "laboratoires"
        if businessCategory == "administration":
            return "services"

    if businessCategory == "pedagogy":
        return "personnels_composantes"
    else:
        return businessCategory

def structureKey(businessCategory, supannCodeEntite):
    def structurePrefix(businessCategory):
        if oldKeys:
            if businessCategory == "pedagogy":
                return "ufr_"
            elif businessCategory == "research":
                return "research_center_"
            elif businessCategory == "administration":
                return "service_"
        return "structure_"
    return structurePrefix(businessCategory) + supannCodeEntite

def write_to_file(doc, name):
    w = codecs.open(name, "w", "utf-8");
    doc.writexml(w, encoding = "UTF-8")

def checkAndIndent(xmlFile):
    tmp_file = xmlFile + ".tmp"
    os.rename(xmlFile, tmp_file)
    if subprocess.call(["xmllint", "--format", "-o", xmlFile, tmp_file]) != 0:
        exit("xmllint failed. install libxml2-utils?")
    os.remove(tmp_file)

def configureLogger(logger):
    hdlr = logging.FileHandler(logFileName)
	
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)

def regexFilterAndGetGroup(regex, n, l):
    r = []
    for e in l:
        matches = re.match(regex, e)
        if matches:
            r.append(matches.group(n))
    return r

def regexFirstMatch(regex, s):
    matches = re.match(regex, s)
    if not matches:
        exit('"' + s + '" is expected to match regex ' + regex)
    return matches.group(1)

def createNode(tag, children):
    node = doc.createElement(tag)
    for child in children:
	node.appendChild(child)
    return node

def createNodeWithText(tag, text):
    return createNode(tag, [doc.createTextNode(text)])

def computeMembersRegexTester(membersList):
    testValues = []
    attribute_name = None
    for elt in membersList:
        if "mainTester" in elt:
            test = elt["mainTester"]
        else:
            testers = elt["testers"]
            if len(testers) != 1:
                exit("expected only one test-group")
            if len(testers[0]) != 1:
                exit("expected only one test")
            test = testers[0][0]

        if attribute_name == None:
            attribute_name = test["attribute-name"]
        testValues.append(test["test-value"])

        if test["tester-class"] != attributeStringEqualsIgnoreCaseTester:
            exit("expected tester-class attributeStringEqualsIgnoreCaseTester on all members tester")
        if attribute_name != test["attribute-name"]:
            exit("expected same attribute-name on all members tester")

    if attribute_name == None: raise EmptyMembersList

    return regexTester(attribute_name, inListRegex(testValues))

def testerToTestNode(tester, e):
    if tester == membersRegexTester:
        tester = computeMembersRegexTester(e["membersList"])

    attrs = [ createNodeWithText("attribute-name", tester["attribute-name"]),
              createNodeWithText("tester-class", tester["tester-class"]),
              createNodeWithText("test-value", tester["test-value"]) ]
    return createNode("test", attrs)

def inListRegex(l):
    vals = [re.escape(v) for v in l]
    return "^(" + "|".join(vals) + ")$"

def tester(attribute_name, test_value, tester_class):
    if typo3 and not attribute_name.startswith("HTTP_SHIB_"):
        attribute_name = typo3attrs[attribute_name]
    return { "tester-class": tester_class, "attribute-name": attribute_name, "test-value": test_value }

def regexTester(attribute_name, test_value):
    return tester(attribute_name, test_value, "org.jasig.portal.groups.pags.testers.RegexTester")

def exactTester(attribute_name, test_value):
    return tester(attribute_name, test_value, "org.jasig.portal.groups.pags.testers.StringEqualsIgnoreCaseTester")

uuids = {}
def checkUniqueRaw(e, typ):
    global uuids
    value = e[typ]
    h = uuids.setdefault(typ, {})
    if value in h: exit(("duplicate %s %s (conflicting keys: %s %s)" % (typ, value, e["raw_key"], h[value])).encode('utf-8'))
    h[value] = e["raw_key"]

def checkUnique(e):
    checkUniqueRaw(e, "key")
    checkUniqueRaw(e, "name")
    checkUniqueRaw(e, "description")

def addGroup(hashStore, parentKey, key, name, description, tester, moreOptions = {}):
    addGroupMulti(hashStore, parentKey, key, name, description, [[tester]], moreOptions)

def addGroupMulti(hashStore, parentKey, raw_key, name, description, testers, moreOptions = {}):
    # elimination des points "." dans les nomenclatures des key pour éviter une exception esup               
    key = raw_key.replace(".","_")
    e = {
        "raw_key": raw_key,
        "key": key,
        "parentKey": parentKey,
        "name": name,
        "description": description,
        "testers": testers,
        "skipIfEmpty": False,
        }
    e.update(moreOptions)

    checkUnique(e)

    hashStore[raw_key] = e

def computeNeededParents(hashStore):
    h = {}
    for child in hashStore.itervalues():
        h[child["parentKey"]] = None
    return h

def computeMembersList(hashStore):
    for e in hashStore.itervalues():
        e["membersList"] = []

    for child in hashStore.itervalues():
        if child["parentKey"] == None: continue
        parentKey = child["parentKey"]
        
        if not parentKey in hashStore:
            exit("parent key " + parentKey + " was used by " + child["key"] + " but it was not defined")

        hashStore[parentKey]["membersList"].append(child)

def createGroupMulti(e):
	""" Création de groupes du type :
	<group>
		<group-key>1</group-key>
		<group-name>Users</group-name>
		<group-description>Portal users whose last names equal User</group-description>
		<selection-test>
			<test-group>
				<test>
					<attribute-name>sn</attribute-name>
					<tester-class>org.jasig.portal.groups.pags.testers.StringEqualsIgnoreCaseTester</tester-class>
					<test-value>User</test-value>
				</test>
			        <test>
                                        <attribute-name>2</attribute-name>
                                        <tester-class>org.jasig.portal.groups.pags.testers.StringEqualsIgnoreCaseTester</tester-class>
                                        <test-value>2</test-value>
                                </test>
			</test-group>
		</selection-test>
		<members>
			<member-key>1</member-key>
			<member-key>2</member-key>
		</members>
	</group>
	"""

        if "." in e["key"]:
            exit("group-key " + key + " is invalid: it must not contain '.'")
		
        testGroups = [
            createNode("test-group", [ testerToTestNode(tester, e) for tester in andTesters ])
            for andTesters in e["testers"] ]            

	group = [ createNodeWithText("group-key", e["key"]),
                  createNodeWithText("group-name", e["name"]),	
                  createNodeWithText("group-description", e["description"]),
                  createNode("selection-test", testGroups) ]                           
		
	if len(e["membersList"]) !=0:
		members = []
		for child in e["membersList"]:
			members.append(createNodeWithText("member-key", child["key"]))
		group.append(createNode("members", members))

        return createNode("group", group)

def restrictOnIdp(idp):
    test_idp = exactTester("Shib-Identity-Provider", idp)
    for andTesters in e["testers"]:
        andTesters.append(test_idp)

def ldap_search(ldp, baseDN, retrieveAttributes, filter="(objectclass=*)"):
    ldap_result_id = ldp.search(baseDN, ldap.SCOPE_ONELEVEL, filter, retrieveAttributes) 
    result_set = get_ldap_results(ldp, ldap_result_id)

    logger.info("LDAP results for " + baseDN + " " + filter + "  : "+str(len(result_set)))

    for e in result_set: logger.debug( e[0][0] )

    return [get_ldap_values(e, retrieveAttributes) for e in result_set]

def get_ldap_results(ldp, ldap_result_id):
    result_set = []
    while 1:
        result_type, result_data = ldp.result(ldap_result_id, timeout)
        if (result_data == []):
            return result_set
        else:
            if result_type == ldap.RES_SEARCH_ENTRY:
                result_set.append(result_data)

def get_ldap_value(ldapEntry, attr):
    try:
        l = [e.decode('utf-8') for e in ldapEntry[0][1][attr]]
        if attr == "seeAlso":
            return l
        else:
            if len(l) > 1: exit("attribute " + attr + " is multi-valued")
            return l[0]
    except KeyError:
        return None

def get_ldap_values(ldapEntry, attrs):
    return [get_ldap_value(ldapEntry, attr) for attr in attrs] 

def createCommonRoots(hashStore):
	# Création du conteneur d'étapes avec ses membres
	addGroup(hashStore, None, etudiantsKey(), u"Composantes (étudiants)", u"Toutes les groupes-étapes de l'établissement issus de LDAP", 
                        regexTester("supannEtuEtape", ".+"))

def structureParent(businessCategory, supannCodeEntiteParent):
    # Selon le type d'ou on détermine le type de groupe
    # Création des groupes pour les services
    if businessCategory == "pedagogy" or businessCategory == "research" or businessCategory == "library":
        return businessCategoryKey(businessCategory)
    elif businessCategory == "administration" :
        return businessCategoryKey(businessCategory)
    elif businessCategory == "council":
        # skip silently
        return None
    else:
        print "skipping unknown businessCategory " + businessCategory
        return None

def addSubGroupsForEachPersonnel(composanteKey, supannCodeEntite, mainTester):
    testers = []
    for typ, descr in personnelDescription.iteritems():
        tester = [ mainTester, exactTester('eduPersonAffiliation', typ) ] 
        description_ = "Tous les " + descr + " de "+supannCodeEntite
        addGroupMulti(hashStore, composanteKey, composanteKey+"_"+typ, description_, description_, [tester])
        testers.append(tester)
    return testers


def createGroupsFrom_structures(hashStore, logger, ldp, neededParents):
	result_set = ldap_search(ldp, structuresDN, ['supannCodeEntite','description','businessCategory','supannCodeEntiteParent']) 
	
	for ldapEntry in result_set :	
		supannCodeEntite, description, businessCategory, supannCodeEntiteParent = ldapEntry

                isPedagogy = etudiantsComposanteKey(supannCodeEntite) in neededParents
                key=structureKey(businessCategory, supannCodeEntite)
                mainTester = exactTester('supannEntiteAffectation', supannCodeEntite)

                parent = structureParent(businessCategory, supannCodeEntiteParent)
                if parent == None: continue

		if isPedagogy and businessCategory != "pedagogy":
                    composanteKey = key + "_composante"
                else:
                    composanteKey = key

                if isPedagogy or businessCategory == "pedagogy":
                    testers = addSubGroupsForEachPersonnel(composanteKey, supannCodeEntite, mainTester)
                else:
                    testers = [[mainTester]]

                addGroupMulti(hashStore, parent, key, description, description, testers, { "mainTester": mainTester })

		if composanteKey != key:
                        # duplicate the structure which is both pedagogy and something else
                        parent = businessCategoryKey('pedagogy')
                        description_ = description + " (composante)"
                        addGroupMulti(hashStore, parent, composanteKey, description_, description_, testers, { "mainTester": mainTester })

                if isPedagogy:
                    ### Création des conteneurs d'étapes pour les étudiants
                    addGroupMulti(hashStore, etudiantsKey(), etudiantsComposanteKey(supannCodeEntite), 
                                  description + u" (étudiants)",
                                  u"Toutes les étapes de la composante "+description+" issus de LDAP",
                                  [[ mainTester, exactTester('eduPersonAffiliation', 'student') ]])

        def createConteneur(key, name, description):
            addGroup(hashStore, None, businessCategoryKey(key), name, description, membersRegexTester)

	# Création du conteneur d'UFR avec ses membres
        addGroupMulti(hashStore, None, businessCategoryKey("pedagogy"), "Composantes personnels", "Toutes les composantes de l'etablissement issues de LDAP", 
                      [[ membersRegexTester, 
                         regexTester('eduPersonAffiliation', inListRegex(personnelTypes)) ]])
	
	createConteneur("research", "Laboratoires de recherche", "Tous les laboratoires de l'etablissement issus de LDAP")

	createConteneur("library", u"Bibliothèques", u"Toutes les bibliothèques de l'etablissement issus de LDAP")
	
	# Création du conteneur de services avec ses membres
	createConteneur("administration", "Services", "Tous les services de l'etablissement issu de LDAP")
		

# Création des groupes étapes, par UFR
def createGroupsFrom_etape(hashStore, logger, ldp):
	result_set = ldap_search(ldp, etapesDN, ['ou','description','seeAlso'])

	etapesByUfrList={}
	
	for ldapEntry in result_set :
		ou, description, seeAlso = ldapEntry
		
                ufr = regexFirstMatch("^ou=([^,]*)", seeAlso[0])
                name = u"Etape - " + description

		# Selon le type d'ou on détermine le type de groupe
		# Création des groupes étapes
                addGroup(hashStore, etudiantsComposanteKey(ufr), "diploma_"+ou, name, description, 
                         exactTester('supannEtuEtape', uaiPrefix + ou))

def createGroupsFrom_ou_groups(hashStore, logger, ldp):
            
    # Création du conteneur des groupes LDAP avec ses membres
    addGroup(hashStore, None, "ldapgroups", u"Groupes LDAP", u"Groupes LDAP dans la branche ou=groups", 
             membersRegexTester)
                            
    # Création du conteneur des matières avec ses membres
    addGroup(hashStore, None, "autres_matieres", u"Matières transverses", u"Matières sans composante principale", 
             membersRegexTester, { "skipIfEmpty": True })

    groupsDN="ou=groups,"+baseDN
    result_set = ldap_search(ldp, groupsDN, ['cn','description', 'seeAlso', 'ou'])

    validGroups = {}
    for ldapEntry in result_set :                    
        cn, description, seeAlso, ou = ldapEntry
        validGroups[cn] = 1
            
    for ldapEntry in result_set :                    
        cn, description, seeAlso, ou = ldapEntry
        if description == None: description = cn
                                    
        #si ce sont de matière le nom du groupe esup correspond à la description dans LDAP
        if re.match("^mati([0-9])*",cn) :
            name = u"Matière - " + description

            composantesParent = regexFilterAndGetGroup("ou=([^,]*),ou=structures,.*", 1, seeAlso)
            etapesParent = regexFilterAndGetGroup("ou=([^,]*),ou=[^,]*,ou=diploma,.*", 1, seeAlso)
            if len(etapesParent) == 1:
                parent = "diploma_" + etapesParent[0]
            elif len(composantesParent) == 1:
                parent = etudiantsComposanteKey(composantesParent[0])
            elif len(composantesParent) > 1:
                exit(cn + ": can not handle case of multiple composantesParent " + repr(composantesParent))
            else:
                parent = "autres_matieres"
        elif re.match("^gpelp\..*",cn) :
            codeApogee = regexFirstMatch("^gpelp\.(.*)",cn)
            name = ou + " (" + codeApogee + ")"
            description = description + " (" + codeApogee + ")"
            if len(seeAlso) > 1:
                #print ("skipping group %s (ou=%s): with %d parents %s" % (cn, ou, len(seeAlso), repr(seeAlso)))
                continue
            parent = regexFirstMatch("^cn=([^,]*)", seeAlso[0])
            if not parent in validGroups:
                #print "skipping group " + cn + " with unknown parent " + parent
                continue
        elif re.match("^gpetp.*",cn) :
            codeApogee = regexFirstMatch("^gpetp\.(.*)",cn)
            name = u"Groupe - " + ou + " (gpetp-" + codeApogee + ")"
            description = description + " (" + codeApogee + ")"
            if len(seeAlso) > 1:
                logger.warn("skipping " + cn + ": with multiple etape parents " + repr(seeAlso))
                continue
            parent = "diploma_" + regexFirstMatch("^ou=([^,]*)", seeAlso[0])
        else:   
            name = cn              
            parent = 'ldapgroups'

        if esup_portail3:
            tester = exactTester('memberOf', 'cn=' + cn + "," + groupsDN)
        else:
            tester = exactTester('groups', cn)

        addGroup(hashStore, parent, cn, name, description, tester)

logger = logging.getLogger()

## first you must open a connection to the server
try:
	ldp = ldap.open(ldapServer)
	## searching doesn't require a bind in LDAP V3.  If you're using LDAP v2, set the next line appropriately
	# and do a bind as shown in the above example.
	# you can also set this to ldap.VERSION2 if you're using a v2 directory
	# you should  set the next option to ldap.VERSION2 if you're using a v2 directory
	ldp.protocol_version = ldap.VERSION3
	# Any errors will throw an ldap.LDAPError exception 
	# or related exception so you can ignore the result
	ldp.simple_bind_s(ldapUsername, ldapPassword)
	
		
except ldap.LDAPError, e:
	logger.debug(e)

try:
    configureLogger(logger)

    doc = xml.dom.minidom.parse(inXmlFile)
    groupStore = doc.getElementsByTagName('Group-Store')[0]

    hashStore = {}
    createCommonRoots(hashStore)
    createGroupsFrom_etape(hashStore, logger, ldp)		
    if esup_portail: createGroupsFrom_ou_groups(hashStore, logger, ldp)
    neededParents = computeNeededParents(hashStore) # must be done after getting etapes and groups
    createGroupsFrom_structures(hashStore, logger, ldp, neededParents)

    computeMembersList(hashStore)
    for e in hashStore.itervalues():
        try:
            if restrictIdp: restrictOnIdp(restrictIdp)
            groupStore.appendChild(createGroupMulti(e))
        except EmptyMembersList:
            logger.warn("expected non-empty membersList for " + e["raw_key"])
            if not e["skipIfEmpty"]:
                exit("expected non-empty membersList for " + e["raw_key"])
 
    write_to_file(doc, outXmlFile)
    checkAndIndent(outXmlFile)
		
except ldap.LDAPError, e:
    logger.error(e)
    sys.stderr.write(`e`)
