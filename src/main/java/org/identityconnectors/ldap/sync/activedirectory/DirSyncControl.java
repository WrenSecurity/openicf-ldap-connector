/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2014 ForgeRock AS. All Rights Reserved
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 * Portions Copyright 2022 Wren Security.
 */
/**
 * @author Gael Allioux <gael.allioux@forgerock.com>
 */
package org.identityconnectors.ldap.sync.activedirectory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.naming.ldap.BasicControl;

import org.forgerock.opendj.asn1.ASN1;
import org.forgerock.opendj.asn1.ASN1Writer;

public class DirSyncControl extends BasicControl {

    private static final long serialVersionUID = 1L;

    public static final String OID = "1.2.840.113556.1.4.841";
    /**
     * We need the combination of: LDAP_DIRSYNC_INCREMENTAL_VALUES |
     * LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER | LDAP_DIRSYNC_OBJECT_SECURITY
     */
    private static final int flags = 0x80000801;
    private static final byte[] EMPTY_COOKIE = new byte[0];

    public DirSyncControl() throws IOException {
        super(OID, true, null);
        super.value = setEncodedValue(Integer.MAX_VALUE, EMPTY_COOKIE);
    }

    public DirSyncControl(byte[] cookie) throws IOException {
        super(OID, true, cookie);
        if (cookie == null) {
            cookie = EMPTY_COOKIE;
        }
        super.value = setEncodedValue(Integer.MAX_VALUE, cookie);
    }

    private byte[] setEncodedValue(int maxAttrCount, byte[] cookie) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(64);
        ASN1Writer writer = ASN1.getWriter(buffer);
        writer.writeStartSequence((byte) 48);
        writer.writeInteger(flags);
        writer.writeInteger(maxAttrCount);
        writer.writeOctetString(cookie);
        writer.writeEndSequence();
        return buffer.toByteArray();
    }
}
