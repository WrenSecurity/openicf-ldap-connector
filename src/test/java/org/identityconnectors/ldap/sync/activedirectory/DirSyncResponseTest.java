/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.1.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.1.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Portions Copyright 2022 Wren Security.
 */
package org.identityconnectors.ldap.sync.activedirectory;

import static org.testng.Assert.assertEquals;

import java.io.IOException;

import org.testng.annotations.Test;

public class DirSyncResponseTest {

    @Test
    public void testGetResponseCookie() throws IOException {
        byte[] encoded = { 48, 20, 2, 4, -128, 0, 8, 1, 2, 4, 127, -1, -1, -1, 4, 6, 102, 111, 111, 98, 97, 114 };
        byte[] expected = "foobar".getBytes();
        DirSyncResponseControl control = new DirSyncResponseControl("id", true, encoded);
        assertEquals(control.getResponseCookie(), expected);
    }

}
