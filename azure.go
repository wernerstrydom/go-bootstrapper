package main

import (
    "context"
    "encoding/base32"
    "fmt"
    "hash/fnv"
    "log"
    "os"
    "strings"

    "github.com/Azure/azure-sdk-for-go/sdk/azcore"
    "github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
    "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
    "github.com/microsoftgraph/msgraph-sdk-go"
    graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
    "github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
)

func bootstrap() {
    // Get the AZURE environment variables
    tenantID := os.Getenv("AZURE_TENANT_ID")
    clientID := os.Getenv("AZURE_CLIENT_ID")
    redirectUrl := os.Getenv("AZURE_REDIRECT_URL")

    // if the environment variables are not set, ask the user for them
    if tenantID == "" {
        log.Println("Enter the tenant ID: ")
        fmt.Scanln(&tenantID)
    }

    if clientID == "" {
        log.Println("Enter the client ID: ")
        fmt.Scanln(&clientID)
    }

    if redirectUrl == "" {
        log.Println("Enter the redirect URL: ")
        fmt.Scanln(&redirectUrl)
    }

    // Create a new InteractiveBrowserCredentialOptions
    options := &azidentity.InteractiveBrowserCredentialOptions{
        TenantID:    tenantID,
        ClientID:    clientID,
        RedirectURL: redirectUrl,
    }

    // Create a new InteractiveBrowserCredential
    cred, err := azidentity.NewInteractiveBrowserCredential(options)
    if err != nil {
        log.Fatalln(err)
    }

    var ctx = context.Background()

    graphClient, err := msgraphsdkgo.NewGraphServiceClientWithCredentials(cred, []string{"Application.ReadWrite.All"})
    if err != nil {
        handle(err)
        return
    }
    result, err := graphClient.Me().Get(ctx, nil)
    if err != nil {
        handle(err)
        return
    }

    // check if there's an application with the same name already registered
    appName := "Deployment"
    apps, err := graphClient.Applications().Get(ctx, nil)
    if err != nil {
        handle(err)
        return
    }

    var app *graphmodels.Application
    for _, item := range apps.GetValue() {
        if *item.GetDisplayName() == appName {
            app = item.(*graphmodels.Application)
            break
        }
    }

    if app == nil {
        // register a deployment application using the Graph Client
        app, err = createApplication(graphClient, appName)
        if err != nil {
            handle(err)
            return
        }
    } else {
        log.Println("Application already exists")
    }

    var sp *graphmodels.ServicePrincipal
    sps, err := graphClient.ServicePrincipals().Get(ctx, nil)
    if err != nil {
        handle(err)
        return
    }

    for _, item := range sps.GetValue() {
        if *item.GetAppId() == *app.GetAppId() {
            sp = item.(*graphmodels.ServicePrincipal)
            break
        }
    }

    if sp == nil {
        sp, err = createServicePrincipal(graphClient, app)
        if err != nil {
            handle(err)
            return
        }
    } else {
        log.Println("Service principal already exists")
    }

    fmt.Println("Service Principal: ", *sp.GetId())
    fmt.Println("Application Id: ", *app.GetId())

    objectID := *result.GetId()

    subscription, err := selectSubscription(ctx, cred)
    if err != nil {
        handle(err)
        return
    }
    log.Printf("Using subscription %s (%s)", subscription.DisplayName, subscription.SubscriptionID)

    resourceGroupName := "Deployment"
    location := "westus"

    suffix, err := suffix(resourceGroupName, location, subscription.SubscriptionID)
    if err != nil {
        handle(err)
        return
    }

    prefix := strings.ToLower(resourceGroupName)
    if len(suffix)+len(prefix) > 23 {
        suffix = suffix[:23-len(prefix)]
    }
    vaultName := prefix + "-" + suffix
    err = createResourceGroup(subscription, cred, ctx, resourceGroupName, location)
    if err != nil {
        handle(err)
        return
    }
    log.Printf("Created resource group '%s'", resourceGroupName)

    objectIDs := []string{objectID, *sp.GetId()}
    err = createKeyVault(ctx, cred, subscription, resourceGroupName, location, vaultName, objectIDs)
    if err != nil {
        handle(err)
        return
    }
    log.Printf("Created key vault '%s' in resource group '%s'", vaultName, resourceGroupName)
}

func createServicePrincipal(
    graphClient *msgraphsdkgo.GraphServiceClient,
    app *graphmodels.Application,
) (*graphmodels.ServicePrincipal, error) {
    requestBody := graphmodels.NewServicePrincipal()
    appId := *app.GetAppId()
    requestBody.SetAppId(&appId)

    spResult, err := graphClient.ServicePrincipals().Post(context.Background(), requestBody, nil)
    if err != nil {
        return nil, fmt.Errorf("error creating service principal: %w", err)
    }
    sp := spResult.(*graphmodels.ServicePrincipal)
    return sp, nil
}

func createApplication(graphClient *msgraphsdkgo.GraphServiceClient, appName string) (*graphmodels.Application, error) {
    requestBody := graphmodels.NewApplication()
    displayName := appName
    requestBody.SetDisplayName(&displayName)
    appResult, err := graphClient.Applications().Post(context.Background(), requestBody, nil)
    if err != nil {
        return nil, fmt.Errorf("error creating application: %w", err)
    }

    app := appResult.(*graphmodels.Application)
    return app, nil
}

func handle(err error) {
    switch err.(type) {
    case *odataerrors.ODataError:
        typed := err.(*odataerrors.ODataError)
        fmt.Printf("error:", typed.Error())
        if terr := typed.GetError(); terr != nil {
            fmt.Printf("code: %s", *terr.GetCode())
            fmt.Printf("msg: %s", *terr.GetMessage())
        }
    default:
        fmt.Printf("%T > error: %#v", err, err)
    }
}

func suffix(parts ...string) (string, error) {
    suffix := strings.ToLower(strings.Join(parts, ""))
    suffixBytes := []byte(suffix)
    hash := fnv.New128a()
    _, err := hash.Write(suffixBytes)
    if err != nil {
        return "", fmt.Errorf("failed to write hash: %w", err)
    }
    hashValue := hash.Sum(suffixBytes)

    const enc = "abcdefghijklmnopqrstuvwxyz234567"
    encoding := base32.NewEncoding(enc).WithPadding(base32.NoPadding)

    buf := &strings.Builder{}
    encoder := base32.NewEncoder(encoding, buf)
    _, err = encoder.Write(hashValue)
    if err != nil {
        return "", fmt.Errorf("failed to write encoder: %w", err)
    }
    encoder.Close()

    return buf.String(), nil
}

func createResourceGroup(
    subscription *Subscription,
    cred *azidentity.InteractiveBrowserCredential,
    ctx context.Context,
    resourceGroup string,
    location string,
) error {
    client, err := armresources.NewResourceGroupsClient(subscription.SubscriptionID, cred, nil)
    if err != nil {
        log.Fatalln(err)
    }

    _, err = client.CreateOrUpdate(
        ctx, resourceGroup, armresources.ResourceGroup{
            Location: &location,
        }, nil,
    )

    if err != nil {
        log.Fatalln(err)
    }
    return nil
}

func createKeyVault(
    ctx context.Context,
    credential azcore.TokenCredential,
    subscription *Subscription,
    resourceGroupName string,
    location string,
    vaultName string,
    ownerObjectIds []string,
) error {
    client, err := armkeyvault.NewVaultsClient(subscription.SubscriptionID, credential, nil)
    if err != nil {
        return fmt.Errorf("failed to create key vault client: %w", err)
    }

    var accessPolicies []*armkeyvault.AccessPolicyEntry
    for _, objectID := range ownerObjectIds {
        accessPolicy := &armkeyvault.AccessPolicyEntry{
            ObjectID: to.Ptr(objectID),
            Permissions: &armkeyvault.Permissions{
                Certificates: []*armkeyvault.CertificatePermissions{
                    to.Ptr(armkeyvault.CertificatePermissionsGet),
                    to.Ptr(armkeyvault.CertificatePermissionsList),
                    to.Ptr(armkeyvault.CertificatePermissionsDelete),
                    to.Ptr(armkeyvault.CertificatePermissionsCreate),
                    to.Ptr(armkeyvault.CertificatePermissionsImport),
                    to.Ptr(armkeyvault.CertificatePermissionsUpdate),
                    to.Ptr(armkeyvault.CertificatePermissionsManagecontacts),
                    to.Ptr(armkeyvault.CertificatePermissionsGetissuers),
                    to.Ptr(armkeyvault.CertificatePermissionsListissuers),
                    to.Ptr(armkeyvault.CertificatePermissionsSetissuers),
                    to.Ptr(armkeyvault.CertificatePermissionsDeleteissuers),
                    to.Ptr(armkeyvault.CertificatePermissionsManageissuers),
                    to.Ptr(armkeyvault.CertificatePermissionsRecover),
                    to.Ptr(armkeyvault.CertificatePermissionsPurge),
                },
                Keys: []*armkeyvault.KeyPermissions{
                    to.Ptr(armkeyvault.KeyPermissionsEncrypt),
                    to.Ptr(armkeyvault.KeyPermissionsDecrypt),
                    to.Ptr(armkeyvault.KeyPermissionsWrapKey),
                    to.Ptr(armkeyvault.KeyPermissionsUnwrapKey),
                    to.Ptr(armkeyvault.KeyPermissionsSign),
                    to.Ptr(armkeyvault.KeyPermissionsVerify),
                    to.Ptr(armkeyvault.KeyPermissionsGet),
                    to.Ptr(armkeyvault.KeyPermissionsList),
                    to.Ptr(armkeyvault.KeyPermissionsCreate),
                    to.Ptr(armkeyvault.KeyPermissionsUpdate),
                    to.Ptr(armkeyvault.KeyPermissionsImport),
                    to.Ptr(armkeyvault.KeyPermissionsDelete),
                    to.Ptr(armkeyvault.KeyPermissionsBackup),
                    to.Ptr(armkeyvault.KeyPermissionsRestore),
                    to.Ptr(armkeyvault.KeyPermissionsRecover),
                    to.Ptr(armkeyvault.KeyPermissionsPurge),
                },
                Secrets: []*armkeyvault.SecretPermissions{
                    to.Ptr(armkeyvault.SecretPermissionsGet),
                    to.Ptr(armkeyvault.SecretPermissionsList),
                    to.Ptr(armkeyvault.SecretPermissionsSet),
                    to.Ptr(armkeyvault.SecretPermissionsDelete),
                    to.Ptr(armkeyvault.SecretPermissionsBackup),
                    to.Ptr(armkeyvault.SecretPermissionsRestore),
                    to.Ptr(armkeyvault.SecretPermissionsRecover),
                    to.Ptr(armkeyvault.SecretPermissionsPurge),
                },
            },
            TenantID: to.Ptr(subscription.TenantID),
        }
        accessPolicies = append(accessPolicies, accessPolicy)
    }

    poller, err := client.BeginCreateOrUpdate(
        ctx,
        resourceGroupName,
        vaultName,
        armkeyvault.VaultCreateOrUpdateParameters{
            Location: to.Ptr(location),
            Properties: &armkeyvault.VaultProperties{
                SKU: &armkeyvault.SKU{
                    Name:   to.Ptr(armkeyvault.SKUNameStandard),
                    Family: to.Ptr(armkeyvault.SKUFamilyA),
                },
                TenantID:                     to.Ptr(subscription.TenantID),
                AccessPolicies:               accessPolicies,
                EnablePurgeProtection:        nil,
                EnableRbacAuthorization:      to.Ptr(false),
                EnableSoftDelete:             to.Ptr(true),
                EnabledForDeployment:         to.Ptr(true),
                EnabledForDiskEncryption:     to.Ptr(true),
                EnabledForTemplateDeployment: to.Ptr(true),
                PublicNetworkAccess:          to.Ptr("Enabled"),
            },
        },
        nil,
    )
    if err != nil {
        return fmt.Errorf("failed to create key vault: %w", err)
    }
    _, err = poller.PollUntilDone(ctx, nil)
    if err != nil {
        return fmt.Errorf("failed to poll until done: %w", err)
    }
    return nil
}

func selectSubscription(ctx context.Context, cred *azidentity.InteractiveBrowserCredential) (*Subscription, error) {
    // get the list of subscriptions that the user has access to, and is either a contributor or owner
    client, err := armsubscriptions.NewClient(cred, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create subscription client: %w", err)
    }

    var subscriptions []*Subscription
    pager := client.NewListPager(nil)
    for pager.More() {
        nextResult, err := pager.NextPage(ctx)
        if err != nil {
            return nil, fmt.Errorf("failed to get next page: %w", err)
        }
        for _, subscription := range nextResult.Value {
            // check if subscription is active
            if *subscription.State == armsubscriptions.SubscriptionStateEnabled {
                subscriptions = append(
                    subscriptions, &Subscription{
                        SubscriptionID: *subscription.SubscriptionID,
                        DisplayName:    *subscription.DisplayName,
                        TenantID:       *subscription.TenantID,
                    },
                )
            }
        }
    }

    if len(subscriptions) == 0 {
        return nil, fmt.Errorf("no subscriptions found")
    }

    var subscription *Subscription
    if len(subscriptions) > 1 {
        fmt.Println("Select a subscription:")
        for i, subscription := range subscriptions {
            fmt.Printf("%d. %s (%s)\n", i+1, subscription.DisplayName, subscription.SubscriptionID)
        }
        fmt.Println("Enter the number of the subscription you want to use: ")
        var selection int
        fmt.Scanln(&selection)
        if selection < 1 || selection > len(subscriptions) {
            return nil, fmt.Errorf("invalid selection")
        }
        subscription = subscriptions[selection-1]
    } else {
        subscription = subscriptions[0]
    }
    return subscription, nil
}
