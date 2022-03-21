/*
 * ====================
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2008-2009 Sun Microsystems, Inc. All rights reserved.
 *
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License("CDDL") (the "License").  You may not use this file
 * except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://IdentityConnectors.dev.java.net/legal/license.txt
 * See the License for the specific language governing permissions and limitations
 * under the License.
 *
 * When distributing the Covered Code, include this CDDL Header Notice in each file
 * and include the License file at identityconnectors/legal/license.txt.
 * If applicable, add the following below this CDDL Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * ====================
 *
 * "Portions Copyrighted 2013-2016 Forgerock AS"
 * Portions Copyright 2022 Wren Security.
 */
package org.identityconnectors.ldap.search;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.PagedResultsControl;
import javax.naming.ldap.SortControl;

import org.forgerock.opendj.ldap.controls.VirtualListViewRequestControl;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.QualifiedUid;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.SortKey;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.identityconnectors.ldap.ADUserAccountControl;
import org.identityconnectors.ldap.ADGroupType;
import org.identityconnectors.ldap.ADLdapUtil;
import org.identityconnectors.ldap.GroupHelper;
import org.identityconnectors.ldap.LdapConnection;
import org.identityconnectors.ldap.LdapConstants;
import org.identityconnectors.ldap.LdapEntry;
import org.identityconnectors.ldap.LdapUtil;
import org.identityconnectors.ldap.schema.LdapSchemaMapping;

import static java.util.Collections.singletonList;

import static org.identityconnectors.common.CollectionUtil.newCaseInsensitiveSet;
import static org.identityconnectors.common.CollectionUtil.newSet;
import static org.identityconnectors.common.StringUtil.isBlank;
import static org.identityconnectors.ldap.ADLdapUtil.convertMSEpochToISO8601;
import static org.identityconnectors.ldap.LdapUtil.buildMemberIdAttribute;
import static org.identityconnectors.ldap.LdapUtil.getStringAttrValues;
import static org.identityconnectors.ldap.ADLdapUtil.objectGUIDtoString;
import static org.identityconnectors.ldap.ADLdapUtil.objectSIDtoString;
import static org.identityconnectors.ldap.ADLdapUtil.fetchTokenGroupsByDn;
import static org.identityconnectors.ldap.ADLdapUtil.fetchGroupMembersByRange;

/**
 * A class to perform an LDAP search against a {@link LdapConnection}.
 *
 * @author Andrei Badea
 */
public class LdapSearch {

    private static final Log logger = Log.getLog(LdapSearch.class);
    private final LdapConnection conn;
    private final ObjectClass oclass;
    private final LdapFilter filter;
    private final OperationOptions options;
    private final GroupHelper groupHelper;
    private final String[] baseDNs;
    private final ResultsHandler handler;

    public static Set<String> getAttributesReturnedByDefault(LdapConnection conn, ObjectClass oclass) {
        if (oclass.equals(LdapSchemaMapping.ANY_OBJECT_CLASS)) {
            return newSet(Name.NAME);
        }
        Set<String> result = newCaseInsensitiveSet();
        ObjectClassInfo oci = conn.getSchemaMapping().schema().findObjectClassInfo(oclass.getObjectClassValue());
        if (oci != null) {
            for (AttributeInfo info : oci.getAttributeInfo()) {
                if (info.isReturnedByDefault()) {
                    result.add(info.getName());
                }
            }
        }
        return result;
    }

    public LdapSearch(LdapConnection conn, ObjectClass oclass, LdapFilter filter, ResultsHandler handler, OperationOptions options) {
        this(conn, oclass, filter, handler, options, conn.getConfiguration().getBaseContexts());
    }

    public LdapSearch(LdapConnection conn, ObjectClass oclass, LdapFilter filter, ResultsHandler handler, OperationOptions options, String... baseDNs) {
        this.conn = conn;
        this.oclass = oclass;
        this.filter = filter;
        this.options = options;
        this.baseDNs = baseDNs;
        this.handler = handler;

        groupHelper = new GroupHelper(conn);
    }

    public final void execute() {
        execute(handler);
    }

    /**
     * Performs the search and passes the resulting {@link ConnectorObject}s to
     * the given handler.
     *
     * @param handler the handler.
     * @throws NamingException if a JNDI exception occurs.
     */
    public final void execute(final ResultsHandler handler) {
        final String[] attrsToGetOption = options.getAttributesToGet();
        final Set<String> attrsToGet = getAttributesToGet(attrsToGetOption);
        LdapInternalSearch search = getInternalSearch(attrsToGet);
        search.execute(new LdapSearchResultsHandler() {
            public boolean handle(String baseDN, SearchResult result) throws NamingException {
                return handler.handle(createConnectorObject(baseDN, result, attrsToGet, attrsToGetOption != null));
            }
        });
    }

    /**
     * Executes the query against all configured base DNs and returns the first
     * {@link ConnectorObject} or {@code null}.
     */
    public final ConnectorObject getSingleResult() {
        final String[] attrsToGetOption = options.getAttributesToGet();
        final Set<String> attrsToGet = getAttributesToGet(attrsToGetOption);
        final ConnectorObject[] results = new ConnectorObject[]{null};
        LdapInternalSearch search = getInternalSearch(attrsToGet);
        search.execute(new LdapSearchResultsHandler() {
            public boolean handle(String baseDN, SearchResult result) throws NamingException {
                results[0] = createConnectorObject(baseDN, result, attrsToGet, attrsToGetOption != null);
                return false;
            }
        });
        return results[0];
    }

    private LdapInternalSearch getInternalSearch(Set<String> attrsToGet) {
        // This is a bit tricky. If the LdapFilter has an entry DN,
        // we only need to look at that entry and check whether it matches
        // the native filter. Moreover, when looking at the entry DN
        // we must not throw exceptions if the entry DN does not exist or is
        // not valid -- just as no exceptions are thrown when the native
        // filter doesn't return any values.
        //
        // In the simple case when the LdapFilter has no entryDN, we
        // will just search over our base DNs looking for entries
        // matching the native filter.

        LdapSearchStrategy strategy;
        List<String> baseDNs;
        int searchScope;

        String filterDN = filter != null ? filter.getBaseDN() : null;
        if (filterDN != null) {
            // Would be good to check that filterDN is under the configured base contexts.
            // However, the adapter is likely to pass entries outside the base contexts,
            // so not checking in order to be on the safe side.
            strategy = new DefaultSearchStrategy(true);
            baseDNs = singletonList(filterDN);
            searchScope = filter.getScope();
        } else {
            strategy = getSearchStrategy();
            baseDNs = getBaseDNs();
            searchScope = getLdapSearchScope();
        }

        SearchControls controls = LdapInternalSearch.createDefaultSearchControls();
        Set<String> ldapAttrsToGet = getLdapAttributesToGet(attrsToGet);
        controls.setReturningAttributes(ldapAttrsToGet.toArray(new String[ldapAttrsToGet.size()]));
        controls.setSearchScope(searchScope);

        String optionsFilter = LdapConstants.getSearchFilter(options);
        String userFilter = null;
        if (oclass.equals(ObjectClass.ACCOUNT)) {
            userFilter = conn.getConfiguration().getAccountSearchFilter();
        } else if (oclass.equals(ObjectClass.GROUP)) {
            userFilter = conn.getConfiguration().getGroupSearchFilter();
        }
        String nativeFilter = filter != null ? filter.getNativeFilter() : null;
        return new LdapInternalSearch(conn, getSearchFilter(optionsFilter, nativeFilter, userFilter), baseDNs, strategy, controls);
    }

    private Set<String> getLdapAttributesToGet(Set<String> attrsToGet) {
        Set<String> cleanAttrsToGet = newCaseInsensitiveSet();
        cleanAttrsToGet.addAll(attrsToGet);
        cleanAttrsToGet.remove(LdapConstants.MS_TOKEN_GROUPS_ATTR);
        cleanAttrsToGet.remove(LdapConstants.LDAP_GROUPS_NAME);
        boolean posixGroups = cleanAttrsToGet.remove(LdapConstants.POSIX_GROUPS_NAME);
        Set<String> result = conn.getSchemaMapping().getLdapAttributes(oclass, cleanAttrsToGet, true);
        if (posixGroups) {
            result.add(GroupHelper.getPosixRefAttribute());
        }
        // For compatibility with the adapter, we do not ask the server for DN attributes,
        // such as entryDN; we compute them ourselves. Some servers might not support such attributes anyway.
        result.removeAll(LdapEntry.ENTRY_DN_ATTRS);
        return result;
    }

    /**
     * Creates a {@link ConnectorObject} based on the given search result. The
     * search result name is expected to be a relative one, thus the {@code
     * baseDN} parameter is needed in order to create the whole entry DN, which
     * is used to compute the connector object's name attribute.
     */
    private ConnectorObject createConnectorObject(String baseDN, SearchResult result, Set<String> attrsToGet, boolean emptyAttrWhenNotFound) {
        LdapEntry entry = LdapEntry.create(baseDN, result);

        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(oclass);
        builder.setUid(conn.getSchemaMapping().createUid(oclass, entry));
        builder.setName(conn.getSchemaMapping().createName(oclass, entry));

        // Some server type specific account control
        if (oclass.equals(ObjectClass.ACCOUNT)) {
            try {
                switch (conn.getServerType()) {
                    case MSAD_GC:
                    case MSAD:
                        if (entry.getAttributes().get(ADUserAccountControl.MS_USR_ACCT_CTRL_ATTR) != null) {
                            String uac = entry.getAttributes().get(ADUserAccountControl.MS_USR_ACCT_CTRL_ATTR).get().toString();
                            builder.addAttribute(AttributeBuilder.buildEnabled(!ADUserAccountControl.isAccountDisabled(uac)));
                            builder.addAttribute(AttributeBuilder.build(ADUserAccountControl.DONT_EXPIRE_PASSWORD_NAME, ADUserAccountControl.isDontExpirePassword(uac)));
                            builder.addAttribute(AttributeBuilder.build(ADUserAccountControl.PASSWORD_NOTREQD_NAME, ADUserAccountControl.isPasswordNotReq(uac)));
                            builder.addAttribute(AttributeBuilder.build(ADUserAccountControl.SMARTCARD_REQUIRED_NAME, ADUserAccountControl.isSmartCardRequired(uac)));
                        }
                        if (entry.getAttributes().get(ADUserAccountControl.MSDS_USR_ACCT_CTRL_ATTR) != null) {
                            String uac2 = entry.getAttributes().get(ADUserAccountControl.MSDS_USR_ACCT_CTRL_ATTR).get().toString();
                            builder.addAttribute(AttributeBuilder.buildLockOut(ADUserAccountControl.isAccountLockOut(uac2)));
                            builder.addAttribute(AttributeBuilder.buildPasswordExpired(ADUserAccountControl.isPasswordExpired(uac2)));
                        }
                        break;
                    case MSAD_LDS:
                        if (entry.getAttributes().get(LdapConstants.MS_DS_USER_ACCOUNT_DISABLED) != null) {
                            builder.addAttribute(AttributeBuilder.buildEnabled(!Boolean.parseBoolean(entry.getAttributes().get(LdapConstants.MS_DS_USER_ACCOUNT_DISABLED).get().toString())));
                        } else if (entry.getAttributes().get(LdapConstants.MS_DS_USER_PASSWORD_EXPIRED) != null) {
                            builder.addAttribute(AttributeBuilder.buildPasswordExpired(Boolean.parseBoolean(entry.getAttributes().get(LdapConstants.MS_DS_USER_PASSWORD_EXPIRED).get().toString())));
                        } else if (entry.getAttributes().get(LdapConstants.MS_DS_USER_ACCOUNT_AUTOLOCKED) != null) {
                            builder.addAttribute(AttributeBuilder.buildLockOut(Boolean.parseBoolean(entry.getAttributes().get(LdapConstants.MS_DS_USER_ACCOUNT_AUTOLOCKED).get().toString())));
                        }
                        break;
                    default:
                }
            } catch (NamingException e) {
                logger.warn(e, "Can't read special control attribute: " + e.getExplanation());
            }
        }

        if (oclass.equals(ObjectClass.GROUP) && ADLdapUtil.isServerMSADFamily(conn.getServerType())){
            try {
                if (entry.getAttributes().get(ADGroupType.GROUPTYPE) != null){
                    String groupType = entry.getAttributes().get(ADGroupType.GROUPTYPE).get().toString();
                    builder.addAttribute(AttributeBuilder.build(ADGroupType.GROUP_SCOPE_NAME, ADGroupType.getScope(groupType)));
                    builder.addAttribute(AttributeBuilder.build(ADGroupType.GROUP_TYPE_NAME, ADGroupType.getType(groupType)));
                }
            } catch (NamingException e) {
                logger.warn(e, "Can't read groupType attribute: " + e.getExplanation());
            }
        }

        for (String attrName : attrsToGet) {
            Attribute attribute = null;
            if (attrName.equalsIgnoreCase(Uid.NAME) || attrName.equalsIgnoreCase(Name.NAME)) {
                continue;
            }
            if (LdapConstants.isLdapGroups(attrName)) {
                List<String> ldapGroups = groupHelper.getLdapGroups(entry.getDN().toString());
                attribute = AttributeBuilder.build(LdapConstants.LDAP_GROUPS_NAME, ldapGroups);
            } else if (LdapConstants.isPosixGroups(attrName)) {
                Set<String> posixRefAttrs = getStringAttrValues(entry.getAttributes(), GroupHelper.getPosixRefAttribute());
                List<String> posixGroups = groupHelper.getPosixGroups(posixRefAttrs);
                attribute = AttributeBuilder.build(LdapConstants.POSIX_GROUPS_NAME, posixGroups);
            } else if (LdapConstants.PASSWORD.is(attrName)) {
                attribute = AttributeBuilder.build(attrName, new GuardedString());
            } else if (LdapConstants.MS_GUID_ATTR.equalsIgnoreCase(attrName)) {
                attribute = AttributeBuilder.build(LdapConstants.MS_GUID_ATTR, objectGUIDtoString(entry.getAttributes().get(LdapConstants.MS_GUID_ATTR)));
            } else if (LdapConstants.MS_SID_ATTR.equalsIgnoreCase(attrName)) {
                attribute = AttributeBuilder.build(LdapConstants.MS_SID_ATTR, objectSIDtoString(entry.getAttributes().get(LdapConstants.MS_SID_ATTR)));
            } else if (LdapConstants.MS_TOKEN_GROUPS_ATTR.equalsIgnoreCase(attrName)) {
                attribute = AttributeBuilder.build(LdapConstants.MS_TOKEN_GROUPS_ATTR, fetchTokenGroupsByDn(conn, entry));
            } else if (ADLdapUtil.isServerMSADFamily(conn.getServerType()) && ADUserAccountControl.AD_CONTROLS_DATES.contains(attrName)) {
                attribute = convertMSEpochToISO8601(entry.getAttributes().get(attrName));
            } else if (conn.getConfiguration().isBinaryUid() && conn.getConfiguration().getUidAttribute().equalsIgnoreCase(attrName)) {
                attribute = AttributeBuilder.build(conn.getConfiguration().getUidAttribute(), LdapUtil.formatBinaryUid(
                        entry.getAttributes().get(conn.getConfiguration().getUidAttribute())));
            } else {
                attribute = conn.getSchemaMapping().createAttribute(oclass, attrName, entry, emptyAttrWhenNotFound);
            }

            if (ObjectClass.GROUP.equals(oclass) && conn.getConfiguration().getGroupMemberAttribute().equalsIgnoreCase(attrName)) {
                if (ADLdapUtil.isServerMSADFamily(conn.getServerType())) {
                    // Make sure we're not hitting AD large group issue
                    // see: http://msdn.microsoft.com/en-us/library/ms817827.aspx
                    if (entry.getAttributes().get("member;range=0-1499") != null) {
                        // we're in the limitation
                        attribute = AttributeBuilder.build(attrName, fetchGroupMembersByRange(conn, entry));
                    }
                }
                if (conn.getConfiguration().isGetGroupMemberId()) {
                    // create an extra _memberId attr for groups
                    builder.addAttribute(buildMemberIdAttribute(conn, attribute));
                }
            }
            if (attribute != null) {
                builder.addAttribute(attribute);
            }
        }

        return builder.build();
    }

    /**
     * Creates a search filter which will filter to a given {@link ObjectClass}.
     * It will be composed in order of an optional filter, the native filter
     * from the query and last the user filter. If the user filter has not been
     * defined, the object class filter is used.
     */
    private String getSearchFilter(String optionsFilter, String nativeFilter, String userFilter) {
        StringBuilder builder = new StringBuilder();
        int nonBlank = 0;

        //First, the optionsFilter
        if ((null != optionsFilter) && (!isBlank(optionsFilter))) {
            appendFilter(optionsFilter, builder);
            nonBlank++;
        }
        //Second, the native filter
        if ((null != nativeFilter) && (!isBlank(nativeFilter))) {
            appendFilter(nativeFilter, builder);
            nonBlank++;
        }
        //Last, userFilter. If this latter is null, then append the objectclass filter.
        if ((null != userFilter) && (!isBlank(userFilter))){
            appendFilter(userFilter, builder);
            nonBlank++;
        }
        else {
            String ocFilter = getObjectClassFilter();
            if (!isBlank(ocFilter)) {
                appendFilter(ocFilter, builder);
                nonBlank++;
            }
        }
        if (nonBlank > 1) {
            builder.append(')');
            builder.insert(0,"(&");
        }
        return builder.toString();
    }

    private String getObjectClassFilter() {
        StringBuilder builder = new StringBuilder();
        List<String> ldapClasses = conn.getSchemaMapping().getLdapClasses(oclass);
        boolean and = ldapClasses.size() > 1;
        if (and) {
            builder.append("(&");
        }
        for (String ldapClass : ldapClasses) {
            builder.append("(objectClass=");
            builder.append(ldapClass);
            builder.append(')');
        }
        if (and) {
            builder.append(')');
        }
        return builder.toString();
    }

    private static void appendFilter(String filter, StringBuilder toBuilder) {
        if (!isBlank(filter)) {
            String trimmedUserFilter = filter.trim();
            boolean enclose = filter.charAt(0) != '(';
            if (enclose) {
                toBuilder.append('(');
            }
            toBuilder.append(trimmedUserFilter);
            if (enclose) {
                toBuilder.append(')');
            }
        }
    }

    private List<String> getBaseDNs() {
        List<String> result;
        QualifiedUid container = options.getContainer();
        if (container != null) {
            result = singletonList(LdapSearches.findEntryDN(conn, container.getObjectClass(), container.getUid()));
        } else {
            result = Arrays.asList(baseDNs);
        }
        assert result != null;
        return result;
    }

    private LdapSearchStrategy getSearchStrategy() {
        LdapSearchStrategy strategy;

        boolean useBlocks = conn.getConfiguration().isUseBlocks();
        boolean usePagedResultsControl = conn.getConfiguration().isUsePagedResultControl();
        int pageSize = conn.getConfiguration().getBlockSize();
        SortKey[] sortKeys = null;

        if (options.getSortKeys() != null && options.getSortKeys().length > 0) {
            if (conn.supportsControl(SortControl.OID)) {
                sortKeys = options.getSortKeys();
            }
        }

        if ((null != options.getPageSize() && options.getPageSize() > 0) && conn.supportsControl(PagedResultsControl.OID)) {
            strategy = new PagedSearchStrategy(options.getPageSize(), options.getPagedResultsCookie(), options.getPagedResultsOffset(), (SearchResultsHandler) handler, sortKeys);
        } else if (useBlocks && !usePagedResultsControl && conn.supportsControl(VirtualListViewRequestControl.OID)) {
            String vlvSortAttr = conn.getConfiguration().getVlvSortAttribute();
            strategy = new VlvIndexSearchStrategy(vlvSortAttr, pageSize);
        } else if (useBlocks && conn.supportsControl(PagedResultsControl.OID)) {
            strategy = new SimplePagedSearchStrategy(pageSize, sortKeys);
        } else {
            strategy = new DefaultSearchStrategy(false, sortKeys);
        }
        return strategy;
    }

    private Set<String> getAttributesToGet(String[] attributesToGet) {
        Set<String> result;
        if (attributesToGet != null) {
            result = newCaseInsensitiveSet();
            result.addAll(Arrays.asList(attributesToGet));
            removeNonReadableAttributes(result);
            result.add(Name.NAME);
        } else {
            // This should include Name.NAME, so no need to include it explicitly.
            result = getAttributesReturnedByDefault(conn, oclass);
        }
        // Since Uid is not in the schema, but it is required to construct a ConnectorObject.
        result.add(Uid.NAME);
        // Our password is marked as readable because of sync(). We really can't return it from search.
        if (result.contains(OperationalAttributes.PASSWORD_NAME)) {
            logger.warn("Reading passwords not supported");
            // throw new ConnectorException(conn.format("readingPasswordsNotSupported", null));
        }
        return result;
    }

    @SuppressWarnings("fallthrough")
    private void removeNonReadableAttributes(Set<String> attributes) {
        // Since the groups attributes are fake attributes, we don't want to
        // send them to LdapSchemaMapping. This, for example, avoid an (unlikely)
        // conflict with a custom attribute defined in the server schema.
        boolean ldapGroups = attributes.remove(LdapConstants.LDAP_GROUPS_NAME);
        boolean posixGroups = attributes.remove(LdapConstants.POSIX_GROUPS_NAME);
        conn.getSchemaMapping().removeNonReadableAttributes(oclass, attributes);
        if (ldapGroups) {
            attributes.add(LdapConstants.LDAP_GROUPS_NAME);
        }
        if (posixGroups) {
            attributes.add(LdapConstants.POSIX_GROUPS_NAME);
        }

        // We don't want to send AD account control
        // instead we add the user account control attributes
        if (ObjectClass.ACCOUNT.equals(oclass)) {
            switch (conn.getServerType()) {
                case MSAD_LDS:
                    attributes.add(LdapConstants.MS_DS_USER_ACCOUNT_DISABLED);
                    attributes.add(LdapConstants.MS_DS_USER_ACCOUNT_AUTOLOCKED);
                    attributes.add(LdapConstants.MS_DS_USER_PASSWORD_EXPIRED);
                case MSAD_GC:
                case MSAD:
                    for (String special : ADUserAccountControl.AD_SPECIAL_ATTRIBUTES) {
                        attributes.remove(special);
                    }
                    attributes.remove(OperationalAttributes.ENABLE_NAME);
                    attributes.remove(OperationalAttributes.LOCK_OUT_NAME);
                    attributes.remove(OperationalAttributes.PASSWORD_EXPIRED_NAME);

                    attributes.add(ADUserAccountControl.MS_USR_ACCT_CTRL_ATTR);
                    attributes.add(ADUserAccountControl.MSDS_USR_ACCT_CTRL_ATTR);
                    break;
                default:
            }
        }
        if (ObjectClass.GROUP.equals(oclass) && ADLdapUtil.isServerMSADFamily(conn.getServerType())){
            attributes.remove(ADGroupType.GROUP_SCOPE_NAME);
            attributes.remove(ADGroupType.GROUP_TYPE_NAME);
            attributes.add(ADGroupType.GROUPTYPE);
        }
    }

    private int getLdapSearchScope() {
        String scope = options.getScope();
        if (OperationOptions.SCOPE_OBJECT.equals(scope)) {
            return SearchControls.OBJECT_SCOPE;
        } else if (OperationOptions.SCOPE_ONE_LEVEL.equals(scope)) {
            return SearchControls.ONELEVEL_SCOPE;
        } else if (OperationOptions.SCOPE_SUBTREE.equals(scope) || scope == null) {
            return SearchControls.SUBTREE_SCOPE;
        } else {
            throw new IllegalArgumentException("Invalid search scope " + scope);
        }
    }
}