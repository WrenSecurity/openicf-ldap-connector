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

import java.io.IOException;

import javax.naming.ldap.BasicControl;

import org.forgerock.opendj.asn1.ASN1;
import org.forgerock.opendj.asn1.ASN1Reader;

public class DirSyncResponseControl extends BasicControl {

    public static final String OID = "1.2.840.113556.1.4.841";

    private long flag;
    private byte[] cookie;

    public DirSyncResponseControl(String id, boolean criticality, byte[] value) throws IOException {
        super(id, criticality, value);
        this.cookie = new byte[0];
        if (value != null && value.length > 0) {
            ASN1Reader reader = ASN1.getReader(value);
            reader.readStartSequence();
            this.flag = reader.readInteger();
            reader.readInteger(); // maxlength
            this.cookie = reader.readOctetString().toByteArray();
            reader.readEndSequence();
        }
    }

    public byte[] getResponseCookie() {
        return cookie != null && cookie.length != 0 ? cookie : null;
    }

    public boolean hasMore() {
        return flag != 0;
    }

}