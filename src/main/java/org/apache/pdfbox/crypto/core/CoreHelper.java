/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.pdfbox.crypto.core;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class CoreHelper
{
  public static void closeStream(Closeable stream)
  {
    if (stream != null)
    {
      try
      {
        stream.close();
      }
      catch (IOException ex)
      {
        // nothing to do
      }
    }
  }

  public static void copy(InputStream in, OutputStream out) throws IOException
  {
    requireNonNull(in);
    requireNonNull(out);

    byte[] buffer = new byte[1024];
    try
    {
      int len = in.read(buffer);
      while (len != -1)
      {
        out.write(buffer, 0, len);
        len = in.read(buffer);
      }
    }
    finally
    {
      closeStream(in);
      closeStream(out);

    }
  }

  public static <T> T requireNonNull(T obj)
  {
    if (obj == null)
    {
      throw new NullPointerException();
    }
    return obj;
  }

  public static <T> T[] requireNonNullOrEmpty(T[] obj)
  {
    if (obj == null || obj.length == 0)
    {
      throw new NullPointerException();
    }
    return obj;
  }
}
