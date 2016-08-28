import pyaudio
import wave
import time
import sys

#CHUNK was 1024
CHUNK = 1024
FORMAT = pyaudio.paInt32
CHANNELS = 2
RATE = 44100
RECORD_SECONDS = 600
#WAVE_OUTPUT_FILENAME = "output.wav"

p = pyaudio.PyAudio()

print("Starting recording in 2 seconds...")
time.sleep(2)

stream = p.open(format=FORMAT,
                channels=CHANNELS,
                rate=RATE,
                input=True,
                frames_per_buffer=CHUNK)

print("* recording")

frames = []
#data = stream.read(CHUNK)

for i in range(0, int(RATE / CHUNK * RECORD_SECONDS)):
    data = stream.read(CHUNK)
    frames.append(data[2::4])
#print(type(data))
print("* done recording")

#print("data is: ")
#print(data)

stream.stop_stream()
stream.close()
p.terminate()
'''
wf = wave.open(WAVE_OUTPUT_FILENAME, 'wb')
wf.setnchannels(CHANNELS)
wf.setsampwidth(p.get_sample_size(FORMAT))
wf.setframerate(RATE)
wf.writeframes(b''.join(frames))
wf.close()
'''

with open(sys.argv[1],"wb") as f:
	for x in frames:
		f.write(x)

'''
with open("ascii_output.txt","w") as f:
	for y in frames:
		for x in y:
			f.write(str(x))
			f.write(',')
'''
