#!/usr/bin/python -d
# -*- coding: utf-8 -*-
import ldap, sys, os, string, re, codecs

import ConfigParser
import subprocess
import logging
import datetime

# A. Anli ajout de strftime pour le rotate log par mois
today = datetime.date.today().strftime("%Y-%m")

configFile=sys.argv[1]
outFile=sys.argv[2]
logFileName=sys.argv[3]+str(today)


Config = ConfigParser.ConfigParser()
Config.read(configFile)

def safeConfigGet(section, option):
    if Config.has_option(section, option):
        return Config.get(section, option)
    else:
        return ""

uaiPrefix     = Config.get('common', 'uaiPrefix')
ldapServer    = Config.get('ldap', 'server')
ldapUsername  = Config.get('ldap', 'username')
ldapPassword  = Config.get('ldap', 'password')
baseDN        = Config.get('ldap', 'baseDN')
etapesDN      = Config.get('ldap', 'etapesDN')
structuresDN = "ou=structures,"+baseDN

personnelDescription = {
    'staff': 'personnels administratifs et techniques', 
    'researcher': 'chercheurs', 
    'teacher' : 'enseignants',
    }
personnelTypes = personnelDescription.keys()

timeout=0


def gsh_header():
    return """
ldapGroupsDn = "ou=groups,dc=univ-paris1,dc=fr";
searchDn = "ou=people";
structures_path = "structures";

cron = "30 6 * * * ?"; // 1h after 5h30 (m-a-j harpege->LDAP)

grouperSession = GrouperSession.startRootSession();
addRootStem(structures_path, structures_path);
knownGroups = new HashSet();
"""

def gsh_footer() :
    return """
////////////////////////////////////////////////////////////////////////////////

removeGroup(g) { System.out.println("removing " + g.getName()); g.delete(); }
getStemChilds(stemName) { return StemFinder.findByName(grouperSession, stemName).getChildGroups(); }

// remove dead groups
mayDeleteGroup(g) { if (!knownGroups.contains(g.getName())) removeGroup(g); }
for (g: getStemChilds(structures_path)) mayDeleteGroup(g);
"""

def gsh_one_params(e):
    create = """
////////////////////////////////////////////////////////////////////////////////
ldap = new Hashtable();

"""
    for k, v in e.iteritems():
        if k == "filter":
            # workaround misuse of vt-ldap in grouper-loader:
            # - grouper-loader uses do new SearchFilter(filter) with no args
            # - but vt-ldap always uses ctx.search(dn, filter, filterArgs, searchControls)
            # - DirContext.search seems to call SearchFilter.format which says: 
            #   To escape '{' or '}' (or any other character), use '\'.
            v = v.replace('{', '\\\\{').replace('}', '\\\\}')
        if v == None: 
            continue;
        else:
            create += ('ldap{"%s"} = "%s";') % (k, v.replace('"', '\\"')) + "\n";

    return create;

def gsh_sync_one():
    return """

attrs = new Hashtable(ldap); // get all, including: description businessCategory filter labeledURI
attrs{"cron"} = cron;
attrs{"searchDn"} = searchDn;
attrs{"parentStem"} = structures_path;

attrs{"id"} = ldap{"supannCodeEntite"};
attrs{"name"} = ldap{"ou"};
if (ldap{"parentKey"} != null) attrs{"seeAlso"} = "cn=" + ldap{"parentKey"} + "," + ldapGroupsDn;


getAttributeAssignByName(group, name) { return group.getAttributeDelegate().assignAttributeByName(name).getAttributeAssign(); }
mayAssignAttrValue(group, wantedAttrs, attrName) { if (wantedAttrs{attrName} != null) getAttributeAssignByName(group, "etc:attribute:" + attrName).getValueDelegate().assignValue(wantedAttrs{attrName}); }
getGroup(fullname) { return GroupFinder.findByName(grouperSession, fullname, false); }

// createGroupOnPeopleAttrs(attrs) {
    fullname = attrs{"parentStem"} + ":" + attrs{"id"};
    group = getGroup(fullname);
    if (group == null) group = addGroup(attrs{"parentStem"}, attrs{"id"}, attrs{"name"});
    group.setDescription(attrs{"description"});
    group.store();

    mayAssignAttrValue(group, attrs, "businessCategory");
    mayAssignAttrValue(group, attrs, "labeledURI");
    mayAssignAttrValue(group, attrs, "seeAlso");

    attributeAssign = group.getAttributeDelegate().assignAttribute(LoaderLdapUtils.grouperLoaderLdapAttributeDefName()).getAttributeAssign();
    a = attributeAssign.getAttributeValueDelegate();
    a.assignValue(LoaderLdapUtils.grouperLoaderLdapTypeName(), "LDAP_SIMPLE");
    a.assignValue(LoaderLdapUtils.grouperLoaderLdapServerIdName(), "personLdap");
    a.assignValue(LoaderLdapUtils.grouperLoaderLdapSourceIdName(), "ldap");
    a.assignValue(LoaderLdapUtils.grouperLoaderLdapSubjectAttributeName(), "eduPersonPrincipalName");
    a.assignValue(LoaderLdapUtils.grouperLoaderLdapSubjectIdTypeName(), "subjectId");

    a.assignValue(LoaderLdapUtils.grouperLoaderLdapQuartzCronName(), attrs{"cron"});
    a.assignValue(LoaderLdapUtils.grouperLoaderLdapFilterName(), attrs{"filter"});
    a.assignValue(LoaderLdapUtils.grouperLoaderLdapSearchDnName(), attrs{"searchDn"});

    loaderRunOneJob(group);
    knownGroups.add(fullname);
// }

"""


def write_to_file(hashStore, name):
    w = codecs.open(name, "w", "utf-8");
    w.write(gsh_header())
    for e in hashStore.itervalues():
        w.write(gsh_one_params(e))
        w.write(gsh_sync_one())
    w.write(gsh_footer())
    w.close()

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

def exactTester(attribute_name, test_value):
    return "(" + attribute_name + "=" + test_value + ")"

def orFilterToFilter(l) :
    if len(l) == 1:
        return l[0]
    else:
        return "(|" + "".join(l) + ")"

def andFilterToFilter(l) :
    if len(l) == 1:
        return l[0]
    else:
        return "(&" + "".join(l) + ")"

def personnelFilter() :
    return orFilterToFilter([ exactTester('eduPersonAffiliation', v) for v in personnelTypes ])

def computeNeededParents(hashStore):
    h = {}
    for child in hashStore.itervalues():
        h[child["parentKey"]] = None
    return h

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

def addSubGroupsForEachPersonnel(composanteKey, supannCodeEntite, mainTester):
    testers = []
    for typ, descr in personnelDescription.iteritems():
        tester = [ mainTester, exactTester('eduPersonAffiliation', typ) ] 
        description_ = "Tous les " + descr + " de "+supannCodeEntite
        addGroupMulti(hashStore, composanteKey, composanteKey+"_"+typ, description_, description_, [tester])
        testers.append(tester)
    return testers


def createGroupsFrom_structures(hashStore, logger, ldp, neededParents):
	result_set = ldap_search(ldp, structuresDN, ['supannCodeEntite','supannCodeEntiteParent','description','businessCategory','labeledURI','ou']) 
	
        personnels_composantes = []

        children = {}
	for ldapEntry in result_set :	
		supannCodeEntite = ldapEntry[0]
                supannCodeEntiteParent = ldapEntry[1]
                if supannCodeEntiteParent:
                    children.setdefault(supannCodeEntiteParent, []).append(supannCodeEntite)

        overrideParentKey = {}
	for ldapEntry in result_set :
                ldap = {}
		ldap["supannCodeEntite"], ldap["supannCodeEntiteParent"], ldap["description"], ldap["businessCategory"], ldap["labeledURI"], ldap["ou"] = ldapEntry

                supannCodeEntite = ldap["supannCodeEntite"]

                if not ldap["ou"]:
                    ldap["ou"] = supannCodeEntite

                isPedagogy = "structures:" + supannCodeEntite in neededParents
                isPedagogy = ldap["businessCategory"] == "pedagogy"

                if ldap["businessCategory"] == "council":
                    continue # skip

                if ldap["businessCategory"] == "administration" and len(supannCodeEntite) == 3 and (supannCodeEntite in children):
                    orFilter = [ exactTester('supannEntiteAffectation', supannCodeEntite) ]
                    for c in children[supannCodeEntite]:
                        if len(c) != 4: continue
                        orFilter.append(exactTester('supannEntiteAffectation', c))
                    supannEntiteAffectationFilter = orFilterToFilter(orFilter)
                else:
                    supannEntiteAffectationFilter = exactTester('supannEntiteAffectation', supannCodeEntite)

                # ensure weird accounts do not show up since we configure grouper sources.xml to show only people with eduPersonAffiliation=*
                eduPersonAffiliationFilter = exactTester('eduPersonAffiliation', '*')

                if isPedagogy or ldap["businessCategory"] == "pedagogy":
                    ldap["supannCodeEntite"] += "-personnel"
                    ldap["ou"] += " (personnel)"
                    ldap["description"] += " (personnel)"
                    eduPersonAffiliationFilter = personnelFilter()
                elif ldap["businessCategory"] == "administration" and len(supannCodeEntite) == 4 and len(ldap["supannCodeEntiteParent"]) == 3:
                    ldap["parentKey"] = "structures:" + ldap["supannCodeEntiteParent"]

                ldap["filter"] = andFilterToFilter([ supannEntiteAffectationFilter, eduPersonAffiliationFilter ])

                del ldap["supannCodeEntiteParent"] # cleanup

                key = "structures:" + ldap["supannCodeEntite"]
                hashStore[key] = ldap

# Création des groupes étapes, par UFR
def createGroupsFrom_etape(hashStore, logger, ldp):
	result_set = ldap_search(ldp, etapesDN, ['ou','description','seeAlso'])
	
	for ldapEntry in result_set :
                ldap = {}
		ou, description, seeAlso = ldapEntry
		ldap["ou"], ldap["description"], ldap["seeAlso"] = ou, description, seeAlso
		
                ufr = regexFirstMatch("^ou=([^,]*)", seeAlso[0])
                ldap["name"] = u"Etape - " + description

                ldap["filter"]  = exactTester('eduPersonOrgUnitDN', "ou=" + ou + "," + etapesDN);
                ldap["parentKey"] = "structures:" + ufr

		# Selon le type d'ou on détermine le type de groupe
		# Création des groupes étapes
                hashStore["diploma:" + ou] = ldap
	

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

    hashStore = {}
    createGroupsFrom_etape(hashStore, logger, ldp)		
    neededParents = computeNeededParents(hashStore) # must be done after getting etapes and groups
    hashStore = {}
    createGroupsFrom_structures(hashStore, logger, ldp, neededParents)

    write_to_file(hashStore, outFile)
		
except ldap.LDAPError, e:
    logger.error(e)
    sys.stderr.write(`e`)
