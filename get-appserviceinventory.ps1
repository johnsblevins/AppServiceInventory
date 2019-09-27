#Login-AzAccount -Environment AzureUSGovernment

$appinfo_array = @()

$subs = Get-AzSubscription

foreach ($sub in $subs)
{
    Select-AzSubscription $sub
    $apps = Get-AzWebApp 

    foreach ($app in $apps)
    {
        $appinfo = new-object psobject

        $appResourceGroup = $app.ResourceGroup
        $appServerFarm = ( ( $app.ServerFarmId -split '/')[-1] )

        Write-Output "Processing: $($app.name)"

        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name Subscription_Id -Value $sub.Id
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name Subscription_Name -Value $sub.Name

        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name App_Id -Value $app.Id
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name App_Name -Value $app.Name
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name App_ResourceGroup -Value $appResourceGroup        
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name App_Kind -Value $app.Kind
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name App_Location -Value $app.Location
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name App_DefaultHostName -Value $app.DefaultHostName
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name App_EnabledHostNames -Value ([string] $app.EnabledHostNames )
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name App_HostNames -Value ([string] $app.HostNames )

        $appplan = Get-AzAppServicePlan -ResourceGroupName $app.ResourceGroup -Name $appServerFarm
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name AppPlan_Id -Value $app.ServerFarmId
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name AppPlan_Name -Value $appServerFarm
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name AppPlan_ResourceGroup  -Value ($appplan.ResourceGroup)
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name AppPlan_MaxNumWorkers -Value ($appplan.MaximumNumberOfWorkers)
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name AppPlan_NumberOfSites  -Value ($appplan.NumberOfSites)
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name AppPlan_Kind  -Value ($appplan.Kind)
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name AppPlan_SKU_Name -Value ($appplan.sku.Name)
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name AppPlan_SKU_Tier -Value ($appplan.sku.Tier)
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name AppPlan_SKU_Size -Value ($appplan.sku.Size)
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name AppPlan_SKU_Family -Value ($appplan.sku.Family)
        Add-Member -InputObject $appinfo -MemberType NoteProperty -Name AppPlan_SKU_Capacity -Value ($appplan.sku.Capacity)

        $ASE_Profile = $appplan.HostingEnvironmentProfile

        if ($ASE_Profile)
        {            
            Add-Member -InputObject $appinfo -MemberType NoteProperty -Name ASE_ID -Value ($ASE_Profile.Id)   
            Add-Member -InputObject $appinfo -MemberType NoteProperty -Name ASE_Name -Value ($ASE_Profile.Name)                     
        }
        else {
            Add-Member -InputObject $appinfo -MemberType NoteProperty -Name ASE_ID -Value ""
            Add-Member -InputObject $appinfo -MemberType NoteProperty -Name ASE_Name -Value ""            
        }
        $appinfo_array += $appinfo
    }

   
}

$appinfo_array | Export-Csv appServiceInventory.csv -NoTypeInformation