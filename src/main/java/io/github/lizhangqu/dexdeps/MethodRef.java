/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.lizhangqu.dexdeps;

public class MethodRef {
    private String mDeclaredClass, mReturnType, mMethodName;
    private String[] mArgTypes;
    private boolean mInternal;

    /**
     * Initializes a new field reference.
     */
    public MethodRef(String declaredClass, String[] argTypes, String returnType,
                     String methodName, boolean internal) {
        mDeclaredClass = declaredClass;
        mArgTypes = argTypes;
        mReturnType = returnType;
        mMethodName = methodName;
        mInternal = internal;
    }

    /**
     * Gets the name of the method's declaring class.
     */
    public String getDeclaredClassName() {
        return mDeclaredClass;
    }

    /**
     * Gets the name of the method's declaring class descriptor.
     */
    public String getDeclaredClassDescriptorName() {
        return Utility.descriptorToDot(getDeclaredClassName());
    }

    /**
     * Gets the method's descriptor.
     */
    public String getDescriptor() {
        return descriptorFromProtoArray(mArgTypes, mReturnType);
    }

    /**
     * Gets the method's name.
     */
    public String getName() {
        return mMethodName;
    }

    /**
     * Gets an array of method argument types.
     */
    public String[] getArgumentTypeNames() {
        return mArgTypes;
    }

    /**
     * Gets the method's return type.  Examples: "Ljava/lang/String;", "[I".
     */
    public String getReturnTypeName() {
        return mReturnType;
    }

    /**
     * set internal
     */
    void setInternal(boolean internal) {
        mInternal = internal;
    }

    /**
     * is internal
     */
    public boolean isInternal() {
        return mInternal;
    }

    /**
     * Returns the method descriptor, given the argument and return type
     * prototype strings.
     */
    private static String descriptorFromProtoArray(String[] protos,
                                                   String returnType) {
        StringBuilder builder = new StringBuilder();

        builder.append("(");
        for (int i = 0; i < protos.length; i++) {
            builder.append(protos[i]);
        }

        builder.append(")");
        builder.append(returnType);

        return builder.toString();
    }

    @Override
    public String toString() {
        return Utility.descriptorToDot(getDeclaredClassName()) +
                "." + getName() + getDescriptor();
    }

}
