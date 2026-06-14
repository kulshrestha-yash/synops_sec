import asyncio
import websockets
import json

async def test():
    uri = 'ws://localhost:8000/ws'
    async with websockets.connect(uri) as ws:
        for i in range(5):
            msg = await ws.recv()
            data = json.loads(msg)
            print(f'[{i+1}] {data["type"]}')

asyncio.run(test())