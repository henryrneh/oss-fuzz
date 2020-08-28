// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "postgres.h"

#include "access/xlog.h"
#include "access/xact.h"
#include "common/username.h"
#include "executor/spi.h"
#include "jit/jit.h"
#include "libpq/libpq.h"
#include "libpq/pqsignal.h"
#include "miscadmin.h"
#include "optimizer/optimizer.h"
#include "parser/analyze.h"
#include "parser/parser.h"
#include "storage/proc.h"
#include "tcop/tcopprot.h"
#include "utils/datetime.h"
#include "utils/memutils.h"
#include "utils/portal.h"
#include "utils/snapmgr.h"
#include "utils/timeout.h"

const char *progname;
static const char *userDoption;
static MemoryContext row_description_context = NULL;
static StringInfoData row_description_buf;
static const char *dbname = NULL;
static const char *username = NULL;


static void
exec_simple_query(const char *query_string)
{
  MemoryContext oldcontext;
  List       *parsetree_list;
  ListCell   *parsetree_item;
  bool        use_implicit_block;

  StartTransactionCommand();
  oldcontext = MemoryContextSwitchTo(MessageContext);

  parsetree_list = raw_parser(query_string);
  MemoryContextSwitchTo(oldcontext);

  use_implicit_block = (list_length(parsetree_list) > 1);

  foreach(parsetree_item, parsetree_list)
    {
      RawStmt    *parsetree = lfirst_node(RawStmt, parsetree_item);
      bool        snapshot_set = false;
      MemoryContext per_parsetree_context = NULL;
      List       *querytree_list,
	*plantree_list;		

      if (use_implicit_block)
	BeginImplicitTransactionBlock();

      if (analyze_requires_snapshot(parsetree))
	{
	  PushActiveSnapshot(GetTransactionSnapshot());
	  snapshot_set = true;
	}

      if (lnext(parsetree_list, parsetree_item) != NULL)
	{
	  per_parsetree_context =
	    AllocSetContextCreate(MessageContext,
				  "per-parsetree message context",
				  ALLOCSET_DEFAULT_SIZES);
	  oldcontext = MemoryContextSwitchTo(per_parsetree_context);
	}
      else
	oldcontext = MemoryContextSwitchTo(MessageContext);

      querytree_list = pg_analyze_and_rewrite(parsetree, query_string,
					      NULL, 0, NULL);
 
      plantree_list = pg_plan_queries(querytree_list, query_string,
				      CURSOR_OPT_PARALLEL_OK, NULL);

      if (per_parsetree_context){
	MemoryContextDelete(per_parsetree_context);
      }
      CommitTransactionCommand();
    }
}

static void fuzzer_exit(){
  if(!username)
    pfree((void *) username);
}


int __attribute__((constructor)) Initialize(void) {
  int argc = 4;
  char *argv[4];
  argv[0] = "tmp_install/usr/local/pgsql/bin/postgres";
  argv[1] = "-D\"temp/data\"";
  argv[2] = "-F";
  argv[3] = "-k\"/tmp/pg_dbfuzz\"";
	
  progname = get_progname(argv[0]);
  MemoryContextInit();

  username = strdup(get_user_name_or_exit(progname));
	 
  InitStandaloneProcess(argv[0]);
  SetProcessingMode(InitProcessing);
  InitializeGUCOptions();
  process_postgres_switches(argc, argv, PGC_POSTMASTER, &dbname);
  dbname = "dbfuzz";

  userDoption = "temp/data";
  SelectConfigFiles(userDoption, progname);

  checkDataDir();
  ChangeToDataDir();
  CreateDataDirLockFile(false);
  LocalProcessControlFile(false);
  InitializeMaxBackends();
		 
  BaseInit();
  InitProcess();
  PG_SETMASK(&UnBlockSig);
  InitPostgres(dbname, InvalidOid, username, InvalidOid, NULL, false);
 
  SetProcessingMode(NormalProcessing);

  BeginReportingGUCOptions();
  process_session_preload_libraries();

  MessageContext = AllocSetContextCreate(TopMemoryContext,
					 "MessageContext",
					 ALLOCSET_DEFAULT_SIZES);
  row_description_context = AllocSetContextCreate(TopMemoryContext,
						  "RowDescriptionContext",
						  ALLOCSET_DEFAULT_SIZES);
  MemoryContextSwitchTo(row_description_context);
  initStringInfo(&row_description_buf);
  MemoryContextSwitchTo(TopMemoryContext);

  PgStartTime = GetCurrentTimestamp();
  whereToSendOutput = DestNone;
  Log_destination = 0;
  atexit(fuzzer_exit);
  return 0;
}


/*
** Main entry point.  The fuzzer invokes this function with each
** fuzzed input.
*/
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  char* query_string;
  sigjmp_buf local_sigjmp_buf;

  query_string = (char*) calloc( (size+1), sizeof(char) );
  memcpy(query_string, data, size);

  if (!sigsetjmp(local_sigjmp_buf, 0))
    {
      PG_exception_stack = &local_sigjmp_buf;
      error_context_stack = NULL;

      disable_all_timeouts(false);
      QueryCancelPending = false;
      pq_comm_reset();
      EmitErrorReport();

      AbortCurrentTransaction();
 
      PortalErrorCleanup();
      SPICleanup();

      jit_reset_after_error();

      MemoryContextSwitchTo(TopMemoryContext);
      FlushErrorState();

      MemoryContextSwitchTo(MessageContext);
      MemoryContextResetAndDeleteChildren(MessageContext);

      InvalidateCatalogSnapshotConditionally();

      SetCurrentStatementStartTimestamp();

      exec_simple_query(query_string);
    }

  free(query_string);
  return 0;
}
