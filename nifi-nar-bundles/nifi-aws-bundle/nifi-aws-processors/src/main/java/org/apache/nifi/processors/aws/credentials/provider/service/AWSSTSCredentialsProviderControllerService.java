/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nifi.processors.aws.credentials.provider.service;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import org.apache.nifi.annotation.behavior.Restricted;
import org.apache.nifi.annotation.behavior.Restriction;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.annotation.lifecycle.OnEnabled;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.RequiredPermission;
import org.apache.nifi.controller.AbstractControllerService;
import org.apache.nifi.controller.ConfigurationContext;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.processor.exception.ProcessException;

import java.util.*;

import static org.apache.nifi.processors.aws.credentials.provider.factory.CredentialPropertyDescriptors.*;

import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.processors.aws.credentials.provider.factory.CredentialPropertyDescriptors;

/**
 * Implementation of AWSCredentialsProviderService interface
 *
 * @see AWSCredentialsProviderService
 */
@CapabilityDescription("TODO")
@Tags({ "aws", "credentials","provider" })
@Restricted(
        restrictions = {
                @Restriction(
                        requiredPermission = RequiredPermission.ACCESS_ENVIRONMENT_CREDENTIALS,
                        explanation = "The default configuration can read environment variables and system properties for credentials"
                )
        }
)
public class AWSSTSCredentialsProviderControllerService extends AbstractControllerService implements AWSCredentialsProviderService {

    private static final List<PropertyDescriptor> properties;

    public static final PropertyDescriptor STS_ACCESS_KEY = new PropertyDescriptor.Builder()
            .name("STS Access Key")
            .displayName("STS Access Key ID")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.VARIABLE_REGISTRY)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .sensitive(true)
            .build();

    public static final PropertyDescriptor STS_SECRET_KEY = new PropertyDescriptor.Builder()
            .name("STS Secret Key")
            .displayName("STS Secret Access Key")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.VARIABLE_REGISTRY)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .sensitive(true)
            .build();

    public static final PropertyDescriptor STS_TOKEN_KEY = new PropertyDescriptor.Builder()
            .name("STS Token Key")
            .displayName("STS Token Key")
            .required(true)
            .expressionLanguageSupported(ExpressionLanguageScope.VARIABLE_REGISTRY)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .sensitive(true)
            .build();

    static {
        final List<PropertyDescriptor> props = new ArrayList<>();
        props.add(STS_ACCESS_KEY);
        props.add(STS_SECRET_KEY);
        props.add(STS_TOKEN_KEY);
        properties = Collections.unmodifiableList(props);
    }

    private volatile AWSCredentialsProvider credentialsProvider;

    @Override
    protected List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return properties;
    }

    @Override
    public AWSCredentialsProvider getCredentialsProvider() throws ProcessException {
        return credentialsProvider;
    }

    @OnEnabled
    public void onConfigured(final ConfigurationContext context) {
        final Map<PropertyDescriptor, String> evaluatedProperties = new HashMap<>(context.getProperties());
        evaluatedProperties.keySet().forEach(propertyDescriptor -> {
            if (propertyDescriptor.isExpressionLanguageSupported()) {
                evaluatedProperties.put(propertyDescriptor,
                        context.getProperty(propertyDescriptor).evaluateAttributeExpressions().getValue());
            }
        });

        String stsAccessKey = evaluatedProperties.get(STS_ACCESS_KEY);
        String stsSecretKey = evaluatedProperties.get(STS_SECRET_KEY);
        String stsSessionToken = evaluatedProperties.get(STS_TOKEN_KEY);

        AWSSessionCredentials tmpCredentials = new BasicSessionCredentials(
                stsAccessKey,
                stsSecretKey,
                stsSessionToken
        );

        this.credentialsProvider = new AWSStaticCredentialsProvider(tmpCredentials);
    }

    @Override
    public void refreshCredentials() throws ProcessException {

    }

    @Override
    public boolean isTokenExpiringSoon(long secondsThreshold) {
        return false;
    }

    @Override
    public String getSessionToken() {
        BasicSessionCredentials credentials = (BasicSessionCredentials) getCredentialsProvider().getCredentials();
        return credentials.getSessionToken();
    }

    @Override
    public String toString() {
        return "AWSSTSCredentialsProviderControllerService[id=" + getIdentifier() + "]";
    }
}