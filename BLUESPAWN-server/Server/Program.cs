// Copyright 2015 gRPC authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Threading.Tasks;
using Grpc.Core;

namespace Gpb
{
    class BLUESPAWNImpl : BLUESPAWN.BLUESPAWNBase
    {
        public override Task<Empty> SendHuntMessage(HuntMessage request, ServerCallContext context)
        {
            return base.SendHuntMessage(request, context);
        }

        public override Task<HandshakeResponse> Handshake(HandshakeRequest request, ServerCallContext context)
        {
            if (request.Contents.Length > 0)
            {
                Console.WriteLine("Recieved: " + request.Contents + " from " + context.Peer);
                return Task.FromResult(new HandshakeResponse { Contents = "Recieved: " + request.Contents });
            }
            else
                return Task.FromResult(new HandshakeResponse { Contents = "Ending Session" });
        }
    }

    class Program
    {
        const int Port = 50051;

        public static void Main(string[] args)
        {
            Server server = new Server
            {
                Services = { BLUESPAWN.BindService(new BLUESPAWNImpl()) },
                Ports = { new ServerPort("localhost", Port, ServerCredentials.Insecure) }
            };
            server.Start();

            Console.WriteLine("BLUESPAWN server listening on port " + Port);
            Console.WriteLine("Press any key to stop the server...");
            Console.ReadKey();

            server.ShutdownAsync().Wait();
        }
    }
}
