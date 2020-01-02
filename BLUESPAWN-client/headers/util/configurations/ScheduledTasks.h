#pragma once
#pragma comment(lib, "taskschd.lib")

#include <windows.h>
//TODO: Pare down as needed
#include <string>
#include <vector>
#include <set>
#include <iostream>
#include <taskschd.h>
#include <chrono>
#include "util/log/Log.h"


namespace ScheduledTasks {
	//TODO: Add any needed typedef and variables

	//STUFF WANTED:
	/*
		Interface Defined For:
			Next Runtime - handled by ScheduledTask::getRuntime()
				Ability to change - handled by ScheduledTask::setRuntime(Date)
				Ability to instantly run - handled by ScheduledTask::stop()
				Ability to stop running - handled by ScheduledTask::run()
			Security Descriptor - handled by ScheduledTask::getSecurityDescriptor()
				Ability to change - handled by ScheduledTask::setSecurityDescriptor(std::wstring)
			Enabled - handled by ScheduledTask::getEnabled()
				Ability to change - handled by ScheduledTask::setEnabled(bool)
			State - handled by ScheduledTask::getState()
			Registration info (date, author, etc.) - handled by ScheduledTask::getRegistration()
			Name - handled by ScheduledTask::getTaskName()
			Ability to get scheduled task by task name - handled by TaskCollection::getTasksByName(std::wstring)
			Ability to get tasks by location - handled by TaskCollection::getTasksByLocation(std::wstring, bool)
					Actions - handled by TaskAction
			ActionType - handled by TaskAction::getType()
			Action taken - handled by TaskAction::getActionRepresentation()
				Ability to change - handled by TaskAction::setAction(std::wstring)
			Delete - handled by ScheduledTask::deleteTask()
		Later Tasks:
			Triggers
				Ability to change
			Ability to change name
			Task Path
			Create 
	*/
	class TaskAction {
		//Email and Show Message actions should always be marked as bad, as they are deprecated
		TASK_ACTION_TYPE type;
		std::wstring id;
		IExecAction* internalExec;
		IComHandlerAction* internalCom;
	public:
		//TODO: Constructors
		TaskAction(IAction action);

		~TaskAction();

		TASK_ACTION_TYPE getType();
		std::wstring getActionRepresentation();
		bool setAction(std::wstring newAction);
	};

	class ScheduledTask : public Loggable {
		//TODO: Local variables here

		std::wstring taskName;
		std::chrono::duration runtime;
		std::vector<TaskAction>* actions;
		std::wstring securityDescriptor;
		IRegisteredTask* internalRepresentation;
		ITaskDefinition* internalDefinition;
		TaskRegistration* registration;
	public:
		//TODO: Constructors
		~ScheduledTask();


		bool taskExists();
		
		std::chrono::duration getRunTime();
		bool setRunTime(const std::chrono::duration& runtime);
		std::wstring getTaskName();
		std::wstring getSecurityDescriptor();
		bool setSecurityDescriptor(const std::wstring& descriptor);
		TaskRegistration* getRegistration();
		TASK_STATE getState();
		bool getEnabled();
		bool setEnabled(bool enabled);
		bool stop();
		bool run();//Maybe allow for arguments as well
		bool deleteTask();//Must delete reference to this class after this call
	};

	class TaskRegistration {
		IRegistrationInfo internalReprsentation;
		std::wstring author;
		DATE registrationDate;
	public:
		//TODO:Constructors
		~TaskRegistration();
		std::wstring getAuthor();
		bool setAuthor(const std::wstring& authorName);
		DATE getRegistrationDate();
		bool setRegistrationDate();
	};

	class TaskCollection : ScheduledTask{
		IRegisteredTaskCollection* tasks; 
	public:
		//TODO: Constructors
		TaskCollection(IRegisteredTaskCollection* t);

		~TaskCollection();
		TaskCollection next();
		TaskCollection prev();
		TaskCollection start();
		TaskCollection end();
		bool atBeginning();
		bool atEnd();

		static TaskCollection getTasksByName(std::wstring name);
		static TaskCollection getTasksInFolder(std::wstring relativePath, bool recurse);
	};
}