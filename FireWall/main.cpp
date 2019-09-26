/*
	Copyright (c) Microsoft Corporation

	SYNOPSIS

		Sample code for the Windows Firewall COM interface.
*/

#include <windows.h>
#include <crtdbg.h>
#include <netfw.h>
#include <objbase.h>
#include <oleauto.h>
#include <stdio.h>
// firewall.cpp : Defines the entry point for the console application.
//

/********************************************************************++
Copyright (C) Microsoft. All Rights Reserved.

Abstract:
	This C++ file includes sample code for disabling Windows Firewall
	per profile using the Microsoft Windows Firewall APIs.

--********************************************************************/


#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )


// Forward declarations
HRESULT     WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2);

// Instantiate INetFwPolicy2
HRESULT WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2)
{
	HRESULT hr = S_OK;

	hr = CoCreateInstance(
		__uuidof(NetFwPolicy2),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwPolicy2),
		(void**)ppNetFwPolicy2);

	if (FAILED(hr))
	{
		printf("CoCreateInstance for INetFwPolicy2 failed: 0x%08lxn", hr);
		goto Cleanup;
	}

Cleanup:
	return hr;
}

HRESULT DisableFirewall(INetFwPolicy2 **pNetFwPolicy)
{
	HRESULT hr = S_OK;
	if (NULL == *pNetFwPolicy)
	{
		return S_FALSE;
	}

	INetFwPolicy2 * pNetFwPolicy2 = *pNetFwPolicy;

	// Disable Windows Firewall for the Domain profile
	hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, FALSE);
	if (FAILED(hr))
	{
		printf("put_FirewallEnabled failed for Domain: 0x%08lxn", hr);
		return S_FALSE;
	}

	// Disable Windows Firewall for the Private profile
	hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, FALSE);
	if (FAILED(hr))
	{
		printf("put_FirewallEnabled failed for Private: 0x%08lxn", hr);
		return S_FALSE;
	}

	// Disable Windows Firewall for the Public profile
	hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, FALSE);
	if (FAILED(hr))
	{
		printf("put_FirewallEnabled failed for Public: 0x%08lxn", hr);
		return S_FALSE;
	}
	   
	return hr;
}

HRESULT EnableFirewall(INetFwPolicy2 **pNetFwPolicy)
{
	HRESULT hr = S_OK;
	if (NULL == *pNetFwPolicy)
	{
		return S_FALSE;
	}
	
	INetFwPolicy2 * pNetFwPolicy2 = *pNetFwPolicy;
	
	// Enable Windows Firewall for the Domain profile
	hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, TRUE);
	if (FAILED(hr))
	{
		printf("put_FirewallEnabled failed for Domain: 0x%08lxn", hr);
		return S_FALSE;
	}

	// Enable Windows Firewall for the Private profile
	hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, TRUE);
	if (FAILED(hr))
	{
		printf("put_FirewallEnabled failed for Private: 0x%08lxn", hr);
		return S_FALSE;
	}

	// Enable Windows Firewall for the Public profile
	hr = pNetFwPolicy2->put_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, TRUE);
	if (FAILED(hr))
	{
		printf("put_FirewallEnabled failed for Public: 0x%08lxn", hr);
		return S_FALSE;
	}

	return hr;
}

HRESULT AddFireWallRule(INetFwPolicy2 **pNetFwPolicy, NET_FW_RULE_DIRECTION_ eDirection, NET_FW_ACTION eAction)
{
	HRESULT hr = S_FALSE;

	INetFwRules *pFwRules = NULL;
	INetFwRule *pFwRule = NULL;

	if (NULL == *pNetFwPolicy)
	{
		return S_FALSE;
	}

	INetFwPolicy2 * pNetFwPolicy2 = *pNetFwPolicy;

	long CurrentProfilesBitMask = 0;

	BSTR bstrRuleName = SysAllocString(L"CYBER_OUTBOUND_RULE2");
	BSTR bstrRuleNameRemove = SysAllocString(L"CYBER_OUTBOUND_RULE");
	BSTR bstrRuleDescription = SysAllocString(L"Allow outbound network traffic from my Application over TCP port 4000");
	BSTR bstrRuleGroup = SysAllocString(L"Cybereason");
	BSTR bstrRuleApplication = SysAllocString(L"Any");
	BSTR bstrRuleLPorts = SysAllocString(L"4000");
	//-------------------------

	hr = pNetFwPolicy2->get_Rules(&pFwRules);
	if (FAILED(hr))
	{
		printf("get_Rules failed: 0x%08lx\n", hr);
		//TODO
		//goto Cleanup;
	}

	// Retrieve Current Profiles bitmask
	hr = pNetFwPolicy2->get_CurrentProfileTypes(&CurrentProfilesBitMask);
	if (FAILED(hr))
	{
		printf("get_CurrentProfileTypes failed: 0x%08lx\n", hr);
		//TODO
		//goto Cleanup;
	}

	// When possible we avoid adding firewall rules to the Public profile.
	// If Public is currently active and it is not the only active profile, we remove it from the bitmask
	if ((CurrentProfilesBitMask & NET_FW_PROFILE2_PUBLIC) &&(CurrentProfilesBitMask != NET_FW_PROFILE2_PUBLIC))
	{
		CurrentProfilesBitMask ^= NET_FW_PROFILE2_PUBLIC;
	}

	// Create a new Firewall Rule object.
	hr = CoCreateInstance(
		__uuidof(NetFwRule),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(INetFwRule),
		(void**)&pFwRule);
	if (FAILED(hr))
	{
		printf("CoCreateInstance for Firewall Rule failed: 0x%08lx\n", hr);
		//TODO
		//goto Cleanup;
	}

	// Populate the Firewall Rule object
	pFwRule->put_Name(bstrRuleName);
	pFwRule->put_Description(bstrRuleDescription);
	pFwRule->put_ApplicationName(bstrRuleApplication);
	pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
	pFwRule->put_LocalPorts(bstrRuleLPorts);
	pFwRule->put_Direction(eDirection);
	//pFwRule->put_Direction(NET_FW_RULE_DIR_IN);
	pFwRule->put_Grouping(bstrRuleGroup);
	pFwRule->put_Profiles(CurrentProfilesBitMask);
	pFwRule->put_Action(eAction);
	pFwRule->put_Enabled(VARIANT_TRUE);

	// Add the Firewall Rule
	hr = pFwRules->Add(pFwRule);
	if (FAILED(hr))
	{
		printf("Firewall Rule Add failed: 0x%08lx\n", hr);
		//TODO
		//goto Cleanup;
	}





	//-------------------------
	return hr;
}

HRESULT RemoveFireWallRule(INetFwPolicy2 **pNetFwPolicy,BSTR btsrRuleName )
{
	HRESULT hr = S_FALSE;

	INetFwRules *pFwRules = NULL;
	
	if (NULL == *pNetFwPolicy)
	{
		return S_FALSE;
	}

	INetFwPolicy2 * pNetFwPolicy2 = *pNetFwPolicy;
	hr = pNetFwPolicy2->get_Rules(&pFwRules);

	hr = pFwRules->Remove(btsrRuleName);
	return hr;
}



int __cdecl main()
{
	HRESULT hrComInit = S_FALSE;
	HRESULT hr = S_FALSE;
	BSTR bstrRuleNameDel = SysAllocString(L"CYBER_OUTBOUND_RULE2");
	INetFwPolicy2 *pNetFwPolicy2 = NULL;

	// Initialize COM.
	hrComInit = CoInitializeEx(
		0,
		COINIT_APARTMENTTHREADED
	);

	// Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
	// initialized with a different mode. Since we don't care what the mode is,
	// we'll just use the existing mode.
	if (hrComInit != RPC_E_CHANGED_MODE)
	{
		if (FAILED(hrComInit))
		{
			printf("CoInitializeEx failed: 0x%08lxn", hrComInit);
		}
	}

	// Retrieve INetFwPolicy2
	if SUCCEEDED(hrComInit)
	{
		hr = WFCOMInitialize(&pNetFwPolicy2);
	}

	if SUCCEEDED(hr)
	{
		//hr = AddFireWallRule(&pNetFwPolicy2, NET_FW_RULE_DIR_IN, NET_FW_ACTION_ALLOW);
		//hr = AddFireWallRule(&pNetFwPolicy2, NET_FW_RULE_DIR_OUT, NET_FW_ACTION_ALLOW);
		hr = RemoveFireWallRule(&pNetFwPolicy2, bstrRuleNameDel);
		return 0;
		//No need to continue for now
	}

	if SUCCEEDED(hr)
	{
		hr = DisableFirewall(&pNetFwPolicy2);
	}
	
	if SUCCEEDED(hr)
	{
		hr = EnableFirewall(&pNetFwPolicy2);
	}

	// Release INetFwPolicy2
	if (pNetFwPolicy2 != NULL)
	{
		pNetFwPolicy2->Release();
	}

	// Uninitialize COM.
	if (SUCCEEDED(hrComInit))
	{
		CoUninitialize();
	}

	return 0;
}
