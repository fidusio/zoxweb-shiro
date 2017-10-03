/*
 * Copyright (c) 2012-2017 ZoxWeb.com LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.zoxweb.server.security.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

import org.zoxweb.server.task.RunnableTask;
import org.zoxweb.server.task.TaskEvent;

public abstract class SubjectRunnableTask
    extends RunnableTask
{
	protected final Subject subject;
	
	protected SubjectRunnableTask()
    {
		this(SecurityUtils.getSubject());
	}
	
	protected SubjectRunnableTask(Subject subject)
    {
		this.subject = subject;
	}

	@Override
	public void executeTask(TaskEvent event)
    {
		this.te = event;

		if (subject != null)
		{
			subject.execute(this);
		}
		else
        {
			run();
		}
	}

}
