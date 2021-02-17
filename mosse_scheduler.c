#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <linux/limits.h>
#include <linux/kernel.h>
#include <sched.h>

#define MAX_LENGTH 50 /* Length of /proc filename */

static int predictor_input_pipe = -1;
static int predictor_output_pipe = -1;
static int predictor_pid = -1;


static void send_to_predictor(const char* fmt, ...)
{
    char buffer[512];

    va_list va;
    va_start(va, fmt);
    int count = vsnprintf(buffer, sizeof(buffer) - 1, fmt, va);
    va_end(va);

    if (count < 0) 
    {
        perror("Scheduler: failed to vsnprintf during send_to_scheduler");
        abort();
    } 
    else 
    {
        buffer[count++] = '\n';
        buffer[count] = '\0';

        int written = write(predictor_input_pipe, buffer, count);
        if (written == -1)
        {
            perror("Scheduler: failed to write to scheduler");
            abort();
        }
        else if (written != count)
        {
            fprintf(stderr, "Scheduler: count mismatch during send_to_scheduler\n");
            abort();
        }
    }
}

static void recv_from_predictor(const char* fmt, ...)
{
    int count = 0;
    char buffer[512];

    while (count == 0 || buffer[count-1] != '\n')
    {
        int result = read(predictor_output_pipe, buffer, sizeof(buffer) - count);
        if (result <= 0)
        {
            perror("Scheduler: failed to read from scheduler pipe\n");
            abort();
        }

        count += result;
        assert(count < (int) sizeof(buffer) - 1);
    }

    va_list va;
    va_start(va, fmt);
    vsscanf(buffer, fmt, va);
    va_end(va);
}

static int spawn_predictor(const char* command)
{
    int inpipefd[2] = {-1, -1};
    int outpipefd[2] = {-1, -1};

    if (pipe(inpipefd) == -1 || pipe(outpipefd) == -1)
    {
        perror("Scheduler: failed to create scheduling pipes");
        return 0;
    }

    int pid = fork();
    if (pid == -1)
    {
        perror("Scheduler: failed to fork scheduler");
        close(inpipefd[0]);
        close(inpipefd[1]);
        close(outpipefd[0]);
        close(outpipefd[1]);
        return 0;
    }
    else if (pid == 0)
    {
        dup2(outpipefd[0], STDIN_FILENO);
        dup2(inpipefd[1], STDOUT_FILENO);

        close(outpipefd[1]);
        close(inpipefd[0]);

        // receive SIGTERM once the parent process dies
        prctl(PR_SET_PDEATHSIG, SIGTERM);

        // execute command to executue Python script
        execl("/bin/sh", "sh", "-c", command, NULL);
        perror("Scheduler: execl failed");
        return 0;
    }
    else
    {
        close(outpipefd[0]);
        close(inpipefd[1]);
        predictor_pid = pid;
        predictor_input_pipe = outpipefd[1];
        predictor_output_pipe = inpipefd[0];
        return 1;
    }
}

int transfer_to_LITTLE(pid_t pid)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    return sched_setaffinity(pid, sizeof(mask), &mask);
}

int transfer_to_big(pid_t pid)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(4, &mask);
    return sched_setaffinity(pid, sizeof(mask), &mask);
}

void spawn_benchmark(char *benchmark)
{
    // Create a child process
    int pid = fork();

    int status;

    if (pid == 0) {
        // Convert pid to string
        char mypid[getpid()];
        sprintf(mypid, "%d", getpid());

        printf("CURRENT CORE: %d\n", sched_getcpu());

        // Write to /proc file to set flag
        char *mappings[] = {"0x11", "0x08", "0x16", "0x17", "0x10"};
        int num_events = 5;
        char *procs[] = {"mosse_c1\"", "mosse_c2\"", "mosse_c3\"", "mosse_c4\""};
        int iscycles = 1;
        int cycles_index = 0;
        int cmds = 0;
        int i;
        for (i = 0; i < (num_events + 1); i++) {
            char proc_cmd[200];
            char *map = (i < num_events) ? mappings[i] : "mosse";

            if (iscycles && i == cycles_index) {
                snprintf(proc_cmd, sizeof(proc_cmd), "sudo sh -c \" echo %s > /proc/%s/mosse_cc\" ", map, mypid);
                iscycles = 0;
            }
            else if (i == num_events) {
                snprintf(proc_cmd, sizeof(proc_cmd), "sudo sh -c \" echo %s > /proc/%s/mosse_clock\" ", map, mypid);
            }
            else {
                snprintf(proc_cmd, sizeof(proc_cmd), "sudo sh -c \" echo %s > /proc/%s/%s", map, mypid, procs[cmds++]);
            }
            system(proc_cmd);
        }

        // Run task
        char *args[] = {benchmark, NULL};
        if (execv(args[0], args) == -1) {
            fprintf(stderr, "Error running mosse\n");
            exit(0);
        }
    }
    else {
        // Convert pid to string
        char mypid[pid];
        sprintf(mypid, "%d", pid);

        // Start at LITTLE core
        transfer_to_LITTLE(pid);

        int interval_ms = 200;
        int interval_us = interval_ms*1000; //need this in microseconds for usleep call
        
        char filename[MAX_LENGTH];
        snprintf(filename, sizeof(filename), "/proc/%s/mosse_all", mypid);
        FILE *counters = fopen(filename, "r");
        int current_core = 0;
        
        while (1) {
            if (waitpid(pid, &status, WNOHANG) != 0) {
                kill(predictor_pid, SIGTERM);
                printf("Execution ended\n");
                exit(0);
            }

            // Read /proc file
            char buf[1760]; // 22 (max length of counter value) * 80 (buffer size)
            int size = fread(&buf , 1, sizeof(buf), counters);
            buf[size] = '\0';
            if (size > 0) {
                char *pmcs[5];
                char *pmc = strtok(buf, "\n");
                int i = 0;
                while (pmc != NULL) {
                    pmcs[i++] = pmc;
                    pmc = strtok(NULL, "\n");
                }
                
                int predicted_phase;
                printf("%s,%s,%s,%s,%s\n", pmcs[0], pmcs[1], pmcs[2], pmcs[3], pmcs[4]);
                send_to_predictor("%s,%s,%s,%s,%s,%s", pmcs[0], pmcs[1], pmcs[2], pmcs[3], pmcs[4], current_core);
                recv_from_predictor("%d", &predicted_phase);

                int phase = 0;
                if (phase >= 5) {
                    if (current_core != 0) {
                        transfer_to_LITTLE(pid);
                        current_core = 0;
                    }
                }
                else {
                    if (current_core != 4) {
                        transfer_to_big(pid);
                        current_core = 4;
                    }
                }

                fprintf(stderr, "Value received from predictor: %d\n", predicted_phase);

            }

            // Reset /proc files
            fclose(counters);
            counters = fopen(filename, "r");

            // sleep for 200ms
            usleep(interval_us);
        }
    }
}

int main(int argc, char* argv[])
{
    // start the predictor
    if(!spawn_predictor("python3 ./predictor.py"))
    {
        fprintf(stderr,"Error: spawn predictor\n");        
        return 1;
    }

    spawn_benchmark("./cpumemory");
    return 0;
}
