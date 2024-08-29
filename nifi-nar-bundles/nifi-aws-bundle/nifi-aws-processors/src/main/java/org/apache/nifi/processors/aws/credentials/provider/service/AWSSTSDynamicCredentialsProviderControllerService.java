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
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.time.Instant;

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
public class AWSSTSDynamicCredentialsProviderControllerService extends AbstractControllerService implements AWSCredentialsProviderService {

    private static final List<PropertyDescriptor> properties;

    public static final PropertyDescriptor STS_COMMAND = new PropertyDescriptor.Builder()
            .name("STS Command")
            .displayName("STS Command")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR) //TODO: Improve that
            .sensitive(false)
            .build();

    public long getLastRefreshEpochTime() {
        return lastRefreshEpochTime;
    }

    public boolean isTokenExpiringSoon(long secondsThreshold) {
        long currentTime = Instant.now().getEpochSecond();
        long expirationSeconds = lastRefreshEpochTime + refreshFrequency - currentTime;
        return (expirationSeconds < secondsThreshold);
    }

    private long lastRefreshEpochTime = 0;
    private final long refreshFrequency = 5 * 60;

    public String getSessionToken() {
        // no need for a class check here, the creation code is down below...
        BasicSessionCredentials credentials = (BasicSessionCredentials) getCredentialsProvider().getCredentials();
        return credentials.getSessionToken();
    }

    static {
        final List<PropertyDescriptor> props = new ArrayList<>();
        props.add(STS_COMMAND);
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

    private Map<String, String> executeStsCommand(String command) {
        Map<String, String> stsEnvironmentVariables = new HashMap<String, String>();

        // Split the command string into a command and its arguments
        // TODO: There must be a better library/way to do this...
        // https://chatgpt.com/c/65c9d439-128e-4da9-a973-48dc8c2797e8
        String[] commandSplit = command.split(" ");

        try {
            // Create a ProcessBuilder instance with the command
            ProcessBuilder builder = new ProcessBuilder(commandSplit);

            // Start the process
            Process process = null;
            process = builder.start();

            // Reader for stdout
            BufferedReader stdOutReader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Regular expression to match lines like "export VARIABLE=VALUE"
            Pattern pattern = Pattern.compile("^export\\s+(\\w+)=(.*)$");

            // Read and parse stdout
            String line;
            while ((line = stdOutReader.readLine()) != null) {
                Matcher matcher = pattern.matcher(line);
                if (matcher.matches()) {
                    String variable = matcher.group(1); // Extract VARIABLE
                    String value = matcher.group(2);    // Extract VALUE
                    stsEnvironmentVariables.put(variable, value);  // Store in HashMap
                }
            }

            // Print the parsed variables and values
            //System.out.println("Parsed Environment Variables:");
            //stsEnvironmentVariables.forEach((key, value) -> System.out.println(key + " = " + value));

            // Wait for the process to finish and get the exit code
            int exitCode = process.waitFor();
            //System.out.println("Exit Code: " + exitCode);

        } catch (Exception e) {
            //TODO: Look at other examples of Controller Service to publish the exception in the right place, and do
            // the right handling errors
            e.printStackTrace();
        }

        return stsEnvironmentVariables;
    }

    @OnEnabled
    public void onConfigured(final ConfigurationContext context) {
        newSession(context);

    }

    private synchronized void newSession(ConfigurationContext context) {
        this.lastRefreshEpochTime = Instant.now().getEpochSecond();

        final Map<PropertyDescriptor, String> evaluatedProperties = new HashMap<>(context.getProperties());
        evaluatedProperties.keySet().forEach(propertyDescriptor -> {
            if (propertyDescriptor.isExpressionLanguageSupported()) {
                evaluatedProperties.put(propertyDescriptor,
                        context.getProperty(propertyDescriptor).evaluateAttributeExpressions().getValue());
            }
        });
//        credentialsProvider = credentialsProviderFactory.getCredentialsProvider(evaluatedProperties);
//        getLogger().debug("Using credentials provider: " + credentialsProvider.getClass());

        String stsCommand = evaluatedProperties.get(STS_COMMAND);
        getLogger().info("Going to Execute this command: " + stsCommand);

        Map<String, String> stsEnvironmentVariables = executeStsCommand(stsCommand);
        for (String key : stsEnvironmentVariables.keySet()) {
            //TODO: Hash the password or something...
            getLogger().info("Key -> " + key + ", value -> " + stsEnvironmentVariables.get(key));
            //System.out.println("Key -> " + key + ", value -> " + stsEnvironmentVariables.get(key));
        }


        if (!stsEnvironmentVariables.containsKey("ACCESS_KEY")
            || !stsEnvironmentVariables.containsKey("SECRET_KEY")
            || !stsEnvironmentVariables.containsKey("SESSION_TOKEN"))
        {
            System.out.println("ERROR while trying to find all the variables...");
            //TODO: Finish Error Handling here
        }
        else {
            AWSSessionCredentials tmpCredentials = new BasicSessionCredentials(
                    stsEnvironmentVariables.get("ACCESS_KEY"),
                    stsEnvironmentVariables.get("SECRET_KEY"),
                    stsEnvironmentVariables.get("SESSION_TOKEN"));

            this.credentialsProvider = new AWSStaticCredentialsProvider(tmpCredentials);
            getLogger().info("Using credentials provider: " + credentialsProvider.getClass());
        }
    }

    @Override
    public void refreshCredentials() throws ProcessException {
        long currentTime = Instant.now().getEpochSecond();
        //TODO: Change the mins to the duration of the token or a parameter
        if ((currentTime - lastRefreshEpochTime) < (refreshFrequency - 90)) {
            getLogger().warn("Last Refresh happens less than {} seconds ago, skipping this.", refreshFrequency);
        }
        else {
            getLogger().info("Refresh Credentials from Controller Service started");
            newSession(this.getConfigurationContext());
        }
    }

    @Override
    public String toString() {
        return "AWSSTSDynamicCredentialsProviderControllerService[id=" + getIdentifier() + "]";
    }
}