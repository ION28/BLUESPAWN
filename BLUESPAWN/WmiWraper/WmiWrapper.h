#pragma once  
#ifndef WMI_WRAPPER_H
#define WMI_WRAPPER_H

#ifdef WMI_WRAPPER_EXPORTS
#define WMI_WRAPPER_API  __declspec(dllexport)   
#else  
#define WMI_WRAPPER_API  __declspec(dllimport)   
#endif  

#define _WIN32_DCOM

#include "stdafx.h"
#include <iostream>
#include <vector>
#include <Wbemidl.h>
#include <comdef.h>
#include <map>
#include "json/json.h"
#include <excpt.h>
#include "WmiObjectnameParser.h"

#pragma comment(lib, "wbemuuid.lib")

/**
A simple wrapper to simplify the use of the WMI libraries.
*/

namespace WmiWrapper {
	
	class WMI_WRAPPER_API WmiWrapper {

		public:
			WmiWrapper();
			~WmiWrapper();
			void Release();

			typedef std::map<std::wstring, std::unique_ptr<VARIANT>> WmiMap;

			// Core WMI functions
			/** Queries wmi for instances of a class. Returns nullptr if querry fails. classType should be in the format 'relativeNamespace/className'  */
			std::unique_ptr<std::vector<IWbemClassObject*>> retrieveWmiQuerry(const std::string &classType);
			/** Registers an objectSink to asyncronously recieve events of 'eventType' on objects of 'classType'. 
			    classType should be in the format 'relativeNamespace/className'. Returns a new ObjectSink that must be stored along with the one passed. */
			IWbemObjectSink* registerObjectSink(IWbemObjectSink *pSink, const std::string &eventType, const std::string &classType);

			// Property lists and maps
			/** Constructs a map that connects wstring property identifiers to property values, represented by unique_ptrs to VARIANTs.
			    Caller responsible for deleting propertyMap, and for clearing variants. Returns nullptr if map construction failed. */
			WmiMap* getWmiObjPropMap(IWbemClassObject *pWmiObj);
			/** Returns nullptr if key query failed */
			std::vector<std::wstring>* getWmiObjPropKeys(IWbemClassObject *pWmiObj);
			std::vector<std::unique_ptr<VARIANT>>* getWmiObjPropVals(IWbemClassObject *pWmiObj, std::vector<std::wstring> *pProps);

			// Casting objecs
			/** Does not clear the variant. That is the responsibility of the caller. Returns nullptr if casting fails 
			Furthermore, the IWbemClassObject does not need to be Released. */
			std::unique_ptr< IWbemClassObject, void(*)(IWbemClassObject*)> variantToWmiObj(VARIANT *pVariant);
			/** Returns nullptr if casting fails */
			IWbemClassObject* iUnknownToWmiObj(IUnknown *pUnknown);
			std::wstring wmiObjectToWstring(IWbemClassObject* pWmiObj);
			std::wstring variantToWstring(VARIANT* variant);

		private:
			IWbemServices *pSvc = nullptr; // interface for communicating with WMI
			IUnsecuredApartment *pUnsecApp = nullptr;

			template <class ArrayType>
			HRESULT variantArrayToString(VARIANT *pVariant, std::wostringstream *ws);

			bool wmiObjectToWstring(IWbemClassObject* pWmiObj, Json::Value *root);

			/** Used to get a service handle at a namespace relative to the 'root' namespace. Returns whether or not
			    the handle was retrieved, and if succesful assigns the handle to the IWbemServices double pointer passed in. */
			HRESULT getServicesToNamespace(const std::string &wmiNamespace, IWbemServices **tmpSvc);

	};

}

#endif