/**
   Copyright 2019-2021 Mikhail Paulyshka

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**/

#include "commands/command_coff_createlib.h"
#include "commands/command_pdb_generate.h"
#include "commands/command_pe_exports.h"
#include "commands/command_pe_guidage.h"
#include "commands/command_pe_timestamp.h"

namespace FakePDB {
    class Main {
    public:
        void AddCommand(std::shared_ptr<CommandInterface> i) {
            _commands.push_back(i);
        }

        int Run(int argc, char* argv[]) {
            if (argc < 2) {
                Usage();
                return 0;
            }

            std::string command_name = argv[1];
            for (auto& command : _commands) {
                //check name
                if (command->GetCommandName() != command_name) {
                    continue;
                }

                //check arg count
                if (argc-2 < command->GetArgsMin() || argc-2 > command->GetArgsMax()) {
                    std::cerr << "Invalid number of arguments" << std::endl;
                    for (auto& usage : command->GetCommandUsage()) {
                        std::cout << "Usage      : " << command->GetCommandName() << " " << usage << std::endl;
                    }
                }

                //run
                return command->Run(argc, argv);
            }

            std::cerr << "Command not found" << std::endl;
            Usage();
            return 1;
        }

        void Usage() {
            std::cout << "Available commands" << std::endl << std::endl;

            for (auto& command : _commands) {
                std::cout << "Name       : " << command->GetCommandName() << std::endl;
                std::cout << "Description: " << command->GetCommandDescription() << std::endl;
                for (auto& usage : command->GetCommandUsage()) {
                    std::cout << "Usage      : " << command->GetCommandName() << " " << usage << std::endl;
                }

                std::cout << std::endl;
            }
        }

    private:
        std::vector<std::shared_ptr<CommandInterface>> _commands;
    };
}


int main(int argc, char* argv[]) {
    FakePDB::Main app;

    app.AddCommand(std::make_shared<FakePDB::Commands::CommandCoffCreatelib>());
    app.AddCommand(std::make_shared<FakePDB::Commands::CommandPdbGenerate>());
    app.AddCommand(std::make_shared<FakePDB::Commands::CommandPeExports>());
    app.AddCommand(std::make_shared<FakePDB::Commands::CommandPeGuidAge>());
    app.AddCommand(std::make_shared<FakePDB::Commands::CommandPeTimestamp>());

    return app.Run(argc, argv);
}
