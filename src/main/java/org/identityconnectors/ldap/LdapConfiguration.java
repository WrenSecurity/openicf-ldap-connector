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
 * Portions Copyrighted 2013-2016 ForgeRock AS
 * Portions Copyright 2022 Wren Security.
 */
package org.identityconnectors.ldap;

import static org.identityconnectors.common.CollectionUtil.newList;
import static org.identityconnectors.common.StringUtil.isBlank;
import static org.identityconnectors.ldap.LdapUtil.nullAsEmpty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.identityconnectors.common.EqualsHashCodeBuilder;
import org.identityconnectors.common.security.GuardedByteArray;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.common.security.GuardedByteArray.Accessor;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationClass;
import org.identityconnectors.framework.spi.ConfigurationProperty;
import org.identityconnectors.framework.spi.StatefulConfiguration;
import org.identityconnectors.framework.spi.operations.SyncOp;
import org.identityconnectors.ldap.LdapConstants.ServerType;

/**
 * Encapsulates the LDAP connector's configuration.
 *
 * @author Andrei Badea
 */
@ConfigurationClass(skipUnsupported = true)
public class LdapConfiguration extends AbstractConfiguration implements StatefulConfiguration {

    // This variable is not exposed as a config property but is cached
    // at runtime by the connector
    private ServerType serverType = null;

    // XXX should try to connect to the resource.
    // XXX add @ConfigurationProperty.

    static final int DEFAULT_PORT = 389;

    // Exposed configuration properties.

    /**
     * The LDAP host server to connect to.
     */
    private String host;

    /**
     * The port the server is listening on.
     */
    private int port = DEFAULT_PORT;

    /**
     * Whether the port is a secure SSL port.
     */
    private boolean ssl;

    /**
     * Whether to use startTLS.
     */
    private boolean startTLS = false;

    /**
     * LDAP URL's to connect to if the main server specified through the host and port
     * properties is not available.
     */
    private String[] failover = { };

    /**
     * The bind DN for performing operations on the server.
     */
    private String principal;

    /**
     * The bind password associated with the bind DN.
     */
    private GuardedString credentials;

    /**
     * The base DNs for operations on the server.
     */
    private String[] baseContexts = { };

    /**
     * Referral policy. Defaults to 'follow'
     * Values can be: 'follow', 'ignore' or 'throw'
     */

    private String referralsHandling = "follow";

    /**
     * The name of the attribute which the predefined PASSWORD attribute
     * will be written to.
     */
    private String passwordAttribute = "userPassword";

    /**
     * The authentication mechanism to use. Either "simple" or "SASL-GSSAPI".
     * Defaults to "simple"
     */

    private String authType = "simple";

    /**
     * A search filter that any account needs to match in order to be returned.
     */
    private String accountSearchFilter = null;

    /**
     * A search filter that any group needs to match in order to be returned.
     */
    private String groupSearchFilter = null;

    /**
     * The LDAP attribute holding the member for non-POSIX static groups.
     */
    private String groupMemberAttribute = "uniqueMember";

    /**
     * If true, add an extra _memberId attribute to get the group members __UID__
     */
    private boolean getGroupMemberId = false;

    /**
     * If true, will modify group membership of renamed/deleted entries.
     */
    private boolean maintainLdapGroupMembership = false;

    /**
     * If true, will modify POSIX group membership of renamed/deleted entries.
     */
    private boolean maintainPosixGroupMembership = false;

    /**
     * If the server stores passwords in clear text, we will hash them with
     * the algorithm specified here.
     */
    private String passwordHashAlgorithm;

    /**
     * If true, when binding check for the Password Expired control (and also Password Policy control)
     * and throw exceptions (PasswordExpiredException, etc.) appropriately.
     */
    private boolean respectResourcePasswordPolicyChangeAfterReset;

    /**
     * Whether to use block-based LDAP controls like simple paged results or VLV control.
     */
    private boolean useBlocks = false;

    /**
     * The block size for simple paged results and VLV index searches.
     */
    private int blockSize = 100;

    /**
     * If true, simple paged search will be preferred over VLV index search
     * when both are available.
     */
    private boolean usePagedResultControl = false;

    /**
     * The attribute used as the sort key for the VLV index.
     */
    private String vlvSortAttribute = "uid";

    /**
     * The LDAP attribute to map Uid to.
     */
    private String uidAttribute = "entryUUID";

    /**
     * Flag indicating whether UID attribute contains binary value.
     */
    private boolean binaryUid;

    /**
     * Whether to read the schema from the server.
     */
    private boolean readSchema = true;

    /**
     * Whether to use DNS SRV records to find hostname
     */
    private boolean useDNSSRVRecord = false;

    /**
     * what to do when sync token conflicts with cn=changelog lastChangeNumber
     */
    private String resetSyncToken = "never";

    // Sync configuration properties.

    private String[] baseContextsToSynchronize = { };

    private String[] objectClassesToSynchronize = { "inetOrgPerson" };

    private String[] attributesToSynchronize = { };

    private String[] modifiersNamesToFilterOut = { };

    private String accountSynchronizationFilter;

    private String groupSynchronizationFilter;

    private int changeLogBlockSize = 100;

    private String changeNumberAttribute = "changeNumber";

    private boolean filterWithOrInsteadOfAnd;

    private boolean removeLogEntryObjectClassFromFilter = true;

    private boolean synchronizePasswords;

    private String passwordAttributeToSynchronize;

    private GuardedByteArray passwordDecryptionKey;

    private GuardedByteArray passwordDecryptionInitializationVector;

    private boolean useTimestampsForSync = false;

    // Other state.

    private final ObjectClassMappingConfig accountConfig = new ObjectClassMappingConfig(ObjectClass.ACCOUNT,
            newList("top", "person", "organizationalPerson", "inetOrgPerson"), false, newList("uid", "cn"),
            LdapConstants.PASSWORD);

    private final ObjectClassMappingConfig groupConfig = new ObjectClassMappingConfig(ObjectClass.GROUP,
            newList("top", "groupOfUniqueNames"), false, Collections.<String>emptyList());

    // Other state not to be included in hashCode/equals.

    private List<LdapName> baseContextsAsLdapNames;

    private List<LdapName> baseContextsToSynchronizeAsLdapNames;

    private Set<LdapName> modifiersNamesToFilterOutAsLdapNames;

    public LdapConfiguration() {
    }

    /**
     * {@inheritDoc}
     */
    public void validate() {
        checkNotBlank(host, "host.notBlank");

        if (port < 0 || port > 0xffff) {
            failValidation("port.legalValue");
        }

        checkNotEmpty(baseContexts, "baseContexts.notEmpty");
        checkNoBlankValues(baseContexts, "baseContexts.noBlankValues");
        checkNoInvalidLdapNames(baseContexts, "baseContexts.noInvalidLdapNames");
        checkReferralsHandling(referralsHandling, "referralsHandling.invalidPolicy");
        checkPasswordHashAlgorithm(passwordHashAlgorithm, "passwordHashAlgorithm.invalidName");
        checkResetSyncToken(resetSyncToken, "resetSyncToken.invalidPolicy");

        checkNotBlank(passwordAttribute, "passwordAttribute.notBlank");

        checkNotEmpty(accountConfig.getLdapClasses(), "accountObjectClasses.notEmpty");
        checkNoBlankValues(accountConfig.getLdapClasses(), "accountObjectClasses.noBlankValues");

        checkNotEmpty(accountConfig.getShortNameLdapAttributes(), "accountUserNameAttributes.notEmpty");
        checkNoBlankValues(accountConfig.getShortNameLdapAttributes(), "accountUserNameAttributes.noBlankValues");

        checkNotBlank(groupMemberAttribute, "groupMemberAttribute.notBlank");

        if (blockSize <= 0) {
            failValidation("blockSize.legalValue");
        }

        checkNotBlank(vlvSortAttribute, "vlvSortAttribute.notBlank");

        checkNotBlank(uidAttribute, "uidAttribute.notBlank");

        if (baseContextsToSynchronize != null) {
            checkNoBlankValues(baseContextsToSynchronize, "baseContextsToSynchronize.noBlankValues");
            checkNoInvalidLdapNames(baseContextsToSynchronize, "baseContextsToSynchronize.noInvalidLdapNames");
        }

        checkNotEmpty(objectClassesToSynchronize, "objectClassesToSynchronize.notEmpty");
        checkNoBlankValues(objectClassesToSynchronize, "objectClassesToSynchronize.noBlankValues");

        if (attributesToSynchronize != null) {
            checkNoBlankValues(attributesToSynchronize, "attributesToSynchronize.noBlankValues");
        }

        if (modifiersNamesToFilterOut != null) {
            checkNoBlankValues(modifiersNamesToFilterOut, "modifiersNamesToFilterOut.noBlankValues");
            checkNoInvalidLdapNames(modifiersNamesToFilterOut, "modifiersNamesToFilterOut.noInvalidLdapNames");
        }

        checkNotBlank(changeNumberAttribute, "changeNumberAttribute.notBlank");

        if (changeLogBlockSize <= 0) {
            failValidation("changeLogBlockSize.legalValue");
        }

        if (synchronizePasswords) {
            checkNotBlank(passwordAttributeToSynchronize, "passwordAttributeToSynchronize.notBlank");
            checkNotBlank(passwordDecryptionKey, "decryptionKey.notBlank");
            checkNotBlank(passwordDecryptionInitializationVector, "decryptionInitializationVector.notBlank");
        }
    }

    private void checkNotBlank(String value, String errorMessage) {
        if (isBlank(value)) {
            failValidation(errorMessage);
        }
    }

    private void checkNotBlank(GuardedByteArray array, String errorMessage) {
        final int[] length = { 0 };
        if (array != null) {
            array.access(new Accessor() {
                public void access(byte[] clearBytes) {
                    length[0] = clearBytes.length;
                }
            });
        }
        if (length[0] == 0) {
            failValidation(errorMessage);
        }
    }

    private void checkNotEmpty(Collection<?> collection, String errorMessage) {
        if (collection.size() < 1) {
            failValidation(errorMessage);
        }
    }

    private void checkNotEmpty(String[] array, String errorMessage) {
        if (array == null || array.length < 1) {
            failValidation(errorMessage);
        }
    }

    private void checkNoBlankValues(Collection<String> collection, String errorMessage) {
        for (String each : collection) {
            if (isBlank(each)) {
                failValidation(errorMessage);
            }
        }
    }

    private void checkNoBlankValues(String[] array, String errorMessage) {
        for (String each : array) {
            if (isBlank(each)) {
                failValidation(errorMessage);
            }
        }
    }

    private void checkNoInvalidLdapNames(String[] array, String errorMessage) {
        for (String each : array) {
            try {
                new LdapName(each);
            } catch (InvalidNameException e) {
                failValidation(errorMessage, each);
            }
        }
    }

    private void checkReferralsHandling(String ref, String errorMessage){
        if (!ref.matches("follow|ignore|throw")){
            failValidation(errorMessage);
        }
    }

    private void checkPasswordHashAlgorithm(String algo, String errorMessage){
        if ((algo != null) && !algo.matches("(?i:SSHA|SHA|SMD5|MD5|WIN-AD)")){
            failValidation(errorMessage);
        }
    }

    private void checkResetSyncToken(String rule, String errorMessage){
        if ((rule != null) && !rule.matches("(?i:NEVER|FIRST|LAST)")){
            failValidation(errorMessage);
        }
    }

    private void failValidation(String key, Object... args) {
        String message = getConnectorMessages().format(key, null, args);
        throw new ConfigurationException(message);
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public boolean isSsl() {
        return ssl;
    }

    public void setSsl(boolean ssl) {
        this.ssl = ssl;
    }

    public boolean isStartTLS() {
        return startTLS;
    }

    public void setStartTLS(boolean startTLS) {
        this.startTLS = startTLS;
    }

    public String[] getFailover() {
        return failover.clone();
    }

    public void setFailover(String... failover) {
        this.failover = failover;
    }

    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    @ConfigurationProperty(confidential = true)
    public GuardedString getCredentials() {
        return credentials;
    }

    public void setCredentials(GuardedString credentials) {
        this.credentials = credentials != null ? credentials.copy() : null;
    }

    public String getAuthType(){
        return authType;
    }

    public void setAuthType(String authType){
        this.authType = authType;
    }

    public String[] getBaseContexts() {
        return baseContexts.clone();
    }

    public void setBaseContexts(String... baseContexts) {
        this.baseContexts = baseContexts.clone();
    }

    public String getReferralsHandling(){
        return referralsHandling;
    }

    public void setReferralsHandling(String referral){
        this.referralsHandling = referral;
    }

    public String getPasswordAttribute() {
        return passwordAttribute;
    }

    public void setPasswordAttribute(String passwordAttribute) {
        this.passwordAttribute = passwordAttribute;
    }

    public String[] getAccountObjectClasses() {
        List<String> ldapClasses = accountConfig.getLdapClasses();
        return ldapClasses.toArray(new String[ldapClasses.size()]);
    }

    public void setAccountObjectClasses(String... accountObjectClasses) {
        accountConfig.setLdapClasses(Arrays.asList(accountObjectClasses));
    }

    public String[] getAccountUserNameAttributes() {
        List<String> shortNameLdapAttributes = accountConfig.getShortNameLdapAttributes();
        return shortNameLdapAttributes.toArray(new String[shortNameLdapAttributes.size()]);
    }

    public void setAccountUserNameAttributes(String... accountUserNameAttributes) {
        accountConfig.setShortNameLdapAttributes(Arrays.asList(accountUserNameAttributes));
    }

    public String getAccountSearchFilter() {
        return accountSearchFilter;
    }

    public void setAccountSearchFilter(String accountSearchFilter) {
        this.accountSearchFilter = accountSearchFilter;
    }

    public String getGroupSearchFilter() {
        return groupSearchFilter;
    }

    public void setGroupSearchFilter(String groupSearchFilter) {
        this.groupSearchFilter = groupSearchFilter;
    }

    public String[] getGroupObjectClasses() {
        List<String> ldapClasses = groupConfig.getLdapClasses();
        return ldapClasses.toArray(new String[ldapClasses.size()]);
    }

    public void setGroupObjectClasses(String... groupObjectClasses) {
        groupConfig.setLdapClasses(Arrays.asList(groupObjectClasses));
    }

    public String getGroupMemberAttribute() {
        return groupMemberAttribute;
    }

    public void setGroupMemberAttribute(String groupMemberAttribute) {
        this.groupMemberAttribute = groupMemberAttribute;
    }

    public boolean isGetGroupMemberId() {
        return getGroupMemberId;
    }

    public void setGetGroupMemberId(boolean getGroupMemberId) {
        this.getGroupMemberId = getGroupMemberId;
    }

    public boolean isMaintainLdapGroupMembership() {
        return maintainLdapGroupMembership;
    }

    public void setMaintainLdapGroupMembership(boolean maintainLdapGroupMembership) {
        this.maintainLdapGroupMembership = maintainLdapGroupMembership;
    }

    public boolean isMaintainPosixGroupMembership() {
        return maintainPosixGroupMembership;
    }

    public void setMaintainPosixGroupMembership(boolean maintainPosixGroupMembership) {
        this.maintainPosixGroupMembership = maintainPosixGroupMembership;
    }

    public String getPasswordHashAlgorithm() {
        return passwordHashAlgorithm;
    }

    public void setPasswordHashAlgorithm(String passwordHashAlgorithm) {
        this.passwordHashAlgorithm = passwordHashAlgorithm;
    }

    public boolean isRespectResourcePasswordPolicyChangeAfterReset() {
        return respectResourcePasswordPolicyChangeAfterReset;
    }

    public void setRespectResourcePasswordPolicyChangeAfterReset(boolean respectResourcePasswordPolicyChangeAfterReset) {
        this.respectResourcePasswordPolicyChangeAfterReset = respectResourcePasswordPolicyChangeAfterReset;
    }

    public boolean isUseBlocks() {
        return useBlocks;
    }

    public void setUseBlocks(boolean useBlocks) {
        this.useBlocks = useBlocks;
    }

    public int getBlockSize() {
        return blockSize;
    }

    public void setBlockSize(int blockSize) {
        this.blockSize = blockSize;
    }

    public boolean isUsePagedResultControl() {
        return usePagedResultControl;
    }

    public void setUsePagedResultControl(boolean usePagedResultControl) {
        this.usePagedResultControl = usePagedResultControl;
    }

    public String getVlvSortAttribute() {
        return vlvSortAttribute;
    }

    public void setVlvSortAttribute(String vlvSortAttribute) {
        this.vlvSortAttribute = vlvSortAttribute;
    }

    public String getUidAttribute() {
        return uidAttribute;
    }

    public void setUidAttribute(String uidAttribute) {
        this.uidAttribute = uidAttribute;
    }

    public boolean isBinaryUid() {
        return binaryUid;
    }

    public void setBinaryUid(boolean binaryUid) {
        this.binaryUid = binaryUid;
    }

    public boolean isReadSchema() {
        return readSchema;
    }

    public void setReadSchema(boolean readSchema) {
        this.readSchema = readSchema;
    }

    public boolean isUseDNSSRVRecord() {
        return useDNSSRVRecord;
    }

    public void setUseDNSSRVRecord(boolean useDNSSRVRecord) {
        this.useDNSSRVRecord = useDNSSRVRecord;
    }

    public String getResetSyncToken() {return resetSyncToken;}

    public void setResetSyncToken(String resetSyncToken) {this.resetSyncToken = resetSyncToken;}

    // Sync properties getters and setters.

    @ConfigurationProperty(operations = { SyncOp.class })
    public String[] getBaseContextsToSynchronize() {
        return baseContextsToSynchronize.clone();
    }

    public void setBaseContextsToSynchronize(String... baseContextsToSynchronize) {
        this.baseContextsToSynchronize = baseContextsToSynchronize.clone();
    }

    @ConfigurationProperty(operations = { SyncOp.class }, required = true)
    public String[] getObjectClassesToSynchronize() {
        return objectClassesToSynchronize.clone();
    }

    public void setObjectClassesToSynchronize(String... objectClassesToSynchronize) {
        this.objectClassesToSynchronize = objectClassesToSynchronize.clone();
    }

    @ConfigurationProperty(operations = { SyncOp.class })
    public String[] getAttributesToSynchronize() {
        return attributesToSynchronize.clone();
    }

    public void setAttributesToSynchronize(String... attributesToSynchronize) {
        this.attributesToSynchronize = attributesToSynchronize.clone();
    }

    @ConfigurationProperty(operations = { SyncOp.class })
    public String[] getModifiersNamesToFilterOut() {
        return modifiersNamesToFilterOut.clone();
    }

    public void setModifiersNamesToFilterOut(String... modifiersNamesToFilterOut) {
        this.modifiersNamesToFilterOut = modifiersNamesToFilterOut.clone();
    }

    @ConfigurationProperty(operations = { SyncOp.class })
    public String getAccountSynchronizationFilter() {
        return accountSynchronizationFilter;
    }

    public void setAccountSynchronizationFilter(String accountSynchronizationFilter) {
        this.accountSynchronizationFilter = accountSynchronizationFilter;
    }

    @ConfigurationProperty(operations = { SyncOp.class })
    public String getGroupSynchronizationFilter() {
        return groupSynchronizationFilter;
    }

    public void setGroupSynchronizationFilter(String groupSynchronizationFilter) {
        this.groupSynchronizationFilter = groupSynchronizationFilter;
    }

    @ConfigurationProperty(operations = { SyncOp.class }, required = true)
    public int getChangeLogBlockSize() {
        return changeLogBlockSize;
    }

    public void setChangeLogBlockSize(int changeLogBlockSize) {
        this.changeLogBlockSize = changeLogBlockSize;
    }

    @ConfigurationProperty(operations = { SyncOp.class }, required = true)
    public String getChangeNumberAttribute() {
        return changeNumberAttribute;
    }

    public void setChangeNumberAttribute(String changeNumberAttribute) {
        this.changeNumberAttribute = changeNumberAttribute;
    }

    @ConfigurationProperty(operations = { SyncOp.class }, required = false)
    public boolean isUseTimestampsForSync() {
        return useTimestampsForSync;
    }

    public void setUseTimestampsForSync(boolean useTimestampsForSync) {
        this.useTimestampsForSync = useTimestampsForSync;
    }

    @ConfigurationProperty(operations = { SyncOp.class })
    public boolean isFilterWithOrInsteadOfAnd() {
        return filterWithOrInsteadOfAnd;
    }

    public void setFilterWithOrInsteadOfAnd(boolean filterWithOrInsteadOfAnd) {
        this.filterWithOrInsteadOfAnd = filterWithOrInsteadOfAnd;
    }

    @ConfigurationProperty(operations = { SyncOp.class })
    public boolean isRemoveLogEntryObjectClassFromFilter() {
        return removeLogEntryObjectClassFromFilter;
    }

    public void setRemoveLogEntryObjectClassFromFilter(boolean removeLogEntryObjectClassFromFilter) {
        this.removeLogEntryObjectClassFromFilter = removeLogEntryObjectClassFromFilter;
    }

    @ConfigurationProperty(operations = { SyncOp.class })
    public boolean isSynchronizePasswords() {
        return synchronizePasswords;
    }

    public void setSynchronizePasswords(boolean synchronizePasswords) {
        this.synchronizePasswords = synchronizePasswords;
    }

    @ConfigurationProperty(operations = { SyncOp.class })
    public String getPasswordAttributeToSynchronize() {
        return passwordAttributeToSynchronize;
    }

    public void setPasswordAttributeToSynchronize(String passwordAttributeToSynchronize) {
        this.passwordAttributeToSynchronize = passwordAttributeToSynchronize;
    }

    @ConfigurationProperty(operations = { SyncOp.class }, confidential = true)
    public GuardedByteArray getPasswordDecryptionKey() {
        return passwordDecryptionKey;
    }

    public void setPasswordDecryptionKey(GuardedByteArray passwordDecryptionKey) {
        this.passwordDecryptionKey = passwordDecryptionKey != null ? passwordDecryptionKey.copy() : null;
    }

    @ConfigurationProperty(operations = { SyncOp.class }, confidential = true)
    public GuardedByteArray getPasswordDecryptionInitializationVector() {
        return passwordDecryptionInitializationVector;
    }

    public void setPasswordDecryptionInitializationVector(GuardedByteArray passwordDecryptionInitializationVector) {
        this.passwordDecryptionInitializationVector = passwordDecryptionInitializationVector != null ? passwordDecryptionInitializationVector.copy() : null;
    }

    // Getters and setters for configuration properties end here.

    public List<LdapName> getBaseContextsAsLdapNames() {
        if (baseContextsAsLdapNames == null) {
            List<LdapName> result = new ArrayList<LdapName>(baseContexts.length);
            try {
                for (String baseContext : baseContexts) {
                    result.add(new LdapName(baseContext));
                }
            } catch (InvalidNameException e) {
                throw new ConfigurationException(e);
            }
            baseContextsAsLdapNames = result;
        }
        return baseContextsAsLdapNames;
    }

    public List<LdapName> getBaseContextsToSynchronizeAsLdapNames() {
        if (baseContextsToSynchronizeAsLdapNames == null) {
            String[] source = nullAsEmpty(baseContextsToSynchronize);
            List<LdapName> result = new ArrayList<LdapName>(source.length);
            try {
                for (String each : source) {
                    result.add(new LdapName(each));
                }
            } catch (InvalidNameException e) {
                throw new ConfigurationException(e);
            }
            baseContextsToSynchronizeAsLdapNames = result;
        }
        return baseContextsToSynchronizeAsLdapNames;
    }

    public Set<LdapName> getModifiersNamesToFilterOutAsLdapNames() {
        if (modifiersNamesToFilterOutAsLdapNames == null) {
            String[] source = nullAsEmpty(modifiersNamesToFilterOut);
            Set<LdapName> result = new HashSet<LdapName>(source.length);
            try {
                for (String each : source) {
                    result.add(new LdapName(each));
                }
            } catch (InvalidNameException e) {
                throw new ConfigurationException(e);
            }
            modifiersNamesToFilterOutAsLdapNames = result;
        }
        return modifiersNamesToFilterOutAsLdapNames;
    }

    public Map<ObjectClass, ObjectClassMappingConfig> getObjectClassMappingConfigs() {
        HashMap<ObjectClass, ObjectClassMappingConfig> result = new HashMap<ObjectClass, ObjectClassMappingConfig>();
        result.put(accountConfig.getObjectClass(), accountConfig);
        result.put(groupConfig.getObjectClass(), groupConfig);
        return result;
    }

    private EqualsHashCodeBuilder createHashCodeBuilder() {
        EqualsHashCodeBuilder builder = new EqualsHashCodeBuilder();
        // Exposed configuration properties.
        builder.append(host);
        builder.append(port);
        builder.append(ssl);
        builder.append(failover);
        builder.append(principal);
        builder.append(credentials);
        for (String baseContext : baseContexts) {
            builder.append(baseContext);
        }
        builder.append(passwordAttribute);
        builder.append(accountSearchFilter);
        builder.append(groupMemberAttribute);
        builder.append(maintainLdapGroupMembership);
        builder.append(maintainPosixGroupMembership);
        builder.append(passwordHashAlgorithm);
        builder.append(respectResourcePasswordPolicyChangeAfterReset);
        builder.append(useBlocks);
        builder.append(blockSize);
        builder.append(usePagedResultControl);
        builder.append(vlvSortAttribute);
        builder.append(uidAttribute);
        builder.append(binaryUid);
        builder.append(readSchema);
        builder.append(useDNSSRVRecord);
        // Sync configuration properties.
        for (String baseContextToSynchronize : baseContextsToSynchronize) {
            builder.append(baseContextToSynchronize);
        }
        for (String objectClassToSynchronize : objectClassesToSynchronize) {
            builder.append(objectClassToSynchronize);
        }
        for (String attributeToSynchronize : attributesToSynchronize) {
            builder.append(attributeToSynchronize);
        }
        for (String modifiersNameToFilterOut : modifiersNamesToFilterOut) {
            builder.append(modifiersNameToFilterOut);
        }
        builder.append(accountSynchronizationFilter);
        builder.append(changeLogBlockSize);
        builder.append(changeNumberAttribute);
        builder.append(filterWithOrInsteadOfAnd);
        builder.append(removeLogEntryObjectClassFromFilter);
        builder.append(synchronizePasswords);
        builder.append(passwordAttributeToSynchronize);
        builder.append(passwordDecryptionKey);
        builder.append(passwordDecryptionInitializationVector);
        builder.append(resetSyncToken);
        // Other state.
        builder.append(accountConfig);
        builder.append(groupConfig);
        return builder;
    }

    @Override
    public int hashCode() {
        return createHashCodeBuilder().hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof LdapConfiguration) {
            LdapConfiguration that = (LdapConfiguration) obj;
            if (this == that) {
                return true;
            }
            return this.createHashCodeBuilder().equals(that.createHashCodeBuilder());
        }
        return false;
    }

    public void cacheServerType(ServerType serverType) {
        this.serverType = serverType;
    }

    public ServerType getServerType() {
        return serverType;
    }
    // =======================================================================
    // Interface Implementation
    // =======================================================================
    public void release() {}
}
