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

esup_portail  = Config.get('common', 'type') == "esup-portail"
uaiPrefix     = Config.get('common', 'uaiPrefix')
ldapServer    = Config.get('ldap', 'server')
ldapUsername  = Config.get('ldap', 'username')
ldapPassword  = Config.get('ldap', 'password')
baseDN        = Config.get('ldap', 'baseDN')
etapesDN      = Config.get('ldap', 'etapesDN')

personnelDescription = {
    'employee': 'personnels administratifs et techniques', 
    'research': 'chercheurs', 
    'teacher' : 'enseignants',
    }
personnelTypes = personnelDescription.keys()

attributeStringEqualsIgnoreCaseTester="org.jasig.portal.groups.pags.testers.StringEqualsIgnoreCaseTester"

structuresDN = "ou=structures,"+baseDN

timeout=0

def write_to_file(doc, name):
    w = codecs.open(name, "w", "utf-8");
    doc.writexml(w, encoding = "UTF-8")

def checkAndIndent(xmlFile):
    tmp_file = xmlFile + ".tmp"
    os.rename(xmlFile, tmp_file)
    subprocess.check_call(["xmllint", "--format", "-o", xmlFile, tmp_file])
    os.remove(tmp_file)

def configureLogger(logger):
    hdlr = logging.FileHandler(logFileName)
	
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)


def createNode(tag, children):
    node = doc.createElement(tag)
    for child in children:
	node.appendChild(child)
    return node

def createNodeWithText(tag, text):
    return createNode(tag, [doc.createTextNode(text)])

def testerToTestNode(tester):
    attrs = [ createNodeWithText("attribute-name", tester["attribute-name"]),
              createNodeWithText("tester-class", tester["tester-class"]),
              createNodeWithText("test-value", tester["test-value"]) ]
    return createNode("test", attrs)

def theKeys(l):
    return [e["key"] for e in l]
def attrVals(l):
    return [e["attrVal"] for e in l]

def inListRegex(l):
    vals = [re.escape(v) for v in l]
    return "^(" + "|".join(vals) + ")$"

def oneOfAttrVals(l):
    return inListRegex(attrVals(l))

def tester(attribute_name, test_value, tester_class):
    return { "tester-class": tester_class, "attribute-name": attribute_name, "test-value": test_value }

def regexTester(attribute_name, test_value):
    return tester(attribute_name, test_value, "org.jasig.portal.groups.pags.testers.RegexTester")

def exactTester(attribute_name, test_value):
    return tester(attribute_name, test_value, "org.jasig.portal.groups.pags.testers.StringEqualsIgnoreCaseTester")

uuids = {}
def checkUniqueRaw(typ, value):
    global uuids
    h = uuids.setdefault(typ, {})
    if value in h: exit("duplicate " + typ + " " + value)
    h[value] = 1

def checkUnique(key, name, description):
    checkUniqueRaw("key", key)
    checkUniqueRaw("name", name)
    checkUniqueRaw("description", description)

def addGroup(groupStore, key, name, description, tester, membersList=None):
    return addGroupMulti(groupStore, key, name, description, [[tester]], membersList)

def addGroupMulti(groupStore, key, name, description, testers, membersList=None):
    # elimination des points "." dans les nomenclatures des key pour éviter une exception esup               
    key = key.replace(".","_")
    checkUnique(key, name, description)
    group = createGroupMulti(key, name, description, testers, membersList)
    groupStore.appendChild(group)
    return key

def createGroupMulti(key, name, description, testers, membersList):    
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

        if "." in key:
            exit("group-key " + key + " is invalid: it must not contain '.'")
		
        testGroups = [
            createNode("test-group", [ testerToTestNode(tester) for tester in andTesters ])
            for andTesters in testers ]            

	group = [ createNodeWithText("group-key", key),
                  createNodeWithText("group-name", name),	
                  createNodeWithText("group-description", description),
                  createNode("selection-test", testGroups) ]                           
		
	if membersList!=None and len(membersList) !=0:
		members = []
		for key in membersList:
			members.append(createNodeWithText("member-key", key))
		group.append(createNode("members", members))

        return createNode("group", group)

def ldap_search(ldp, baseDN, retrieveAttributes, filter="(objectclass=*)"):
    ldap_result_id = ldp.search(baseDN, ldap.SCOPE_ONELEVEL, filter, retrieveAttributes) 
    result_set = get_ldap_results(ldp, ldap_result_id)

    logger.info("LDAP results for " + baseDN + " " + filter + "  : "+str(len(result_set)))

    for e in result_set: logger.debug( e[0][0] )

    return [get_ldap_simple_values(e, retrieveAttributes) for e in result_set]

def get_ldap_results(ldp, ldap_result_id):
    result_set = []
    while 1:
        result_type, result_data = ldp.result(ldap_result_id, timeout)
        if (result_data == []):
            return result_set
        else:
            if result_type == ldap.RES_SEARCH_ENTRY:
                result_set.append(result_data)

def get_ldap_simple_value(ldapEntry, attr):
    try:
        return ldapEntry[0][1][attr][0].decode('utf-8')
    except KeyError:
        return None

def get_ldap_simple_values(ldapEntry, attrs):
    return [get_ldap_simple_value(ldapEntry, attr) for attr in attrs] 

def createGroupsFrom_structures(groupStore, logger, ldp):
	result_set = ldap_search(ldp, structuresDN, ['supannCodeEntite','description','businessCategory']) 

	members_composantes=[]
        members_laboratoires=[]
        members_services=[]
	
	for ldapEntry in result_set :	
		supannCodeEntite, description, businessCategory = ldapEntry
		
                subList=[]
                simpleTester = exactTester('supannEntiteAffectation', supannCodeEntite)
                testers = [[simpleTester]]
		
		# Selon le type d'ou on détermine le type de groupe
		# Création des groupes pour les services
		if businessCategory == "pedagogy" :
               		key="ufr_"+supannCodeEntite
                        parent = members_composantes
                        testers = []
                        for typ in personnelTypes:
                            tester = [ simpleTester, exactTester('eduPersonAffiliation', typ) ] 
                            description_ = "Tous les " + personnelDescription[typ] + " de "+supannCodeEntite
                            key_ = addGroupMulti(groupStore, key+"_"+typ, description_, description_, [tester])
                            subList.append(key_)
                            testers.append(tester)

		# Création des groupes pour les labos
		elif businessCategory == "research" :
			key="research_center_"+supannCodeEntite
			parent = members_laboratoires
		# Création des groupes pour les services
		else :
			key="service_"+supannCodeEntite
			parent = members_services

                key = addGroupMulti(groupStore, key, description, description, testers, subList)
                parent.append({ "attrVal": supannCodeEntite, "key": key })

        def createConteneur(key, name, description, members):
            tester = regexTester('supannEntiteAffectation', oneOfAttrVals(members))
            addGroup(groupStore, key, name, description, tester, theKeys(members))

	# Création du conteneur d'UFR avec ses membres
	addGroupMulti(groupStore, "composantes", "LDAP Toutes les composantes", "Toutes les composantes de l'etablissement issues de LDAP", 
                      [[ regexTester('supannEntiteAffectation', oneOfAttrVals(members_composantes)), 
                         regexTester('eduPersonAffiliation', inListRegex(personnelTypes)) ]], 
                      theKeys(members_composantes))
	
	# Création du conteneur de labos avec ses membres
	createConteneur("laboratoires", "LDAP Tous les Laboratoires", "Tous les laboratoires de l'etablissement issus de LDAP", 
                        members_laboratoires)
	
	# Création du conteneur de services avec ses membres
	createConteneur("services", "LDAP Tous les Services", "Tous les services de l'etablissement issu de LDAP", 
                        members_services)
		

# Création des groupes étapes, par UFR
def createGroupsFrom_etape(groupStore, logger, ldp):
	result_set = ldap_search(ldp, etapesDN, ['ou','description','seeAlso'])

	etapesByUfrList={}
	
	# On pourrait prendre la liste des ufr issue d'Harpège
	ufrList=[]
	
	for ldapEntry in result_set :
		ou, description, seeAlso = ldapEntry
		
		# Selon le type d'ou on détermine le type de groupe
		# Création des groupes étapes
                key = addGroup(groupStore, "diploma_"+ou, description, description, 
                         exactTester('supannEtuEtape', uaiPrefix + ou))
                ufr = re.match("^ou=([^,]*)", seeAlso).group(1)
		
                #Liste des UFR contenant des diplômes
                etapesByUfrList.setdefault(ufr, []).append(key)
		
		
	for ufr in sorted(etapesByUfrList.keys()) :	
                ou,description = ldap_search(ldp, structuresDN, ['ou','description'], "supannCodeEntite=" + ufr)[0]

		### Création des conteneurs d'étapes par UFR
		addGroup(groupStore, "diploma_composante_"+ufr, u"LDAP Toutes les étapes pour la composante "+description,
                         u"Toutes les étapes de la composante "+description+" issus de LDAP",
                         exactTester("supannEntiteAffectation", ufr), etapesByUfrList[ufr])
	
	# Création du conteneur d'étapes avec ses membres
	ufrKeyList=["diploma_composante_"+ufr for ufr in ufrList]
		
	addGroup(groupStore, "diploma", u"LDAP Toutes les étapes", u"Toutes les groupes-étapes de l'établissement issus de LDAP", 
                        regexTester("supannEtuEtape", ".*"), ufrKeyList)

def createGroupsFrom_ou_groups(groupStore, logger, ldp):
    groupsDN="ou=groups,"+baseDN
    result_set = ldap_search(ldp, groupsDN, ['cn','description'])
            
    matList=[]
    ldapgroupsList=[]
    for ldapEntry in result_set :                    
        cn, description = ldapEntry
        if description == None: description = cn
                                    
        #si ce sont de matière le nom du groupe esup correspond à la description dans LDAP
        if re.match("^mati([0-9])*",cn) :
            name = description
            parent = matList
        else:   
            name = cn              
            parent = ldapgroupsList

        key = addGroup(groupStore, cn, name, description, exactTester('groups', cn))
        parent.append({ "attrVal": cn, "key": key })            
            
    # Création du conteneur des groupes LDAP avec ses membres
    addGroup(groupStore, "ldapgroups", u"Groupes LDAP", u"Groupes LDAP dans la branche ou=groups", 
             regexTester('groups', oneOfAttrVals(ldapgroupsList)), theKeys(ldapgroupsList))
                            
    # Création du conteneur des matières avec ses membres
    addGroup(groupStore, "matieres", u"LDAP Toutes les matières", u"Groupes étudiants par matière", 
             regexTester('groups', '^mati.*'), theKeys(matList))

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

    createGroupsFrom_structures(groupStore, logger, ldp)
    createGroupsFrom_etape(groupStore, logger, ldp)		
    if esup_portail: createGroupsFrom_ou_groups(groupStore, logger, ldp)

    write_to_file(doc, outXmlFile)
    checkAndIndent(outXmlFile)
		
except ldap.LDAPError, e:
    logger.error(e)
    sys.stderr.write(`e`)
